/**
 * credinjector.c - Credential Injection Plugin for Deadlight Proxy
 *
 * Integrates with vault.deadlight over a Unix socket to transparently
 * inject credentials into proxied HTTP(S) requests.
 *
 * Injection strategy by credential type:
 *   token    → Authorization: Bearer <value>
 *   password → check for stored session cookies first; if none,
 *              flag the domain for session capture on next Set-Cookie
 *   ssh_key  → not applicable to HTTP proxy context, ignored
 *
 * Domain matching:
 *   Credentials are matched to domains via the "proxy_match" field in
 *   the credential's metadata JSON, set when adding to vault:
 *
 *     vault add github-api \
 *         --type token \
 *         --value ghp_xxx \
 *         --metadata '{"proxy_match":"api.github.com"}'
 *
 *   The plugin queries vault with GET_CREDENTIAL on first contact with
 *   a domain; results are cached in-process for the plugin lifetime to
 *   avoid a socket round-trip on every request.  The cache is keyed by
 *   domain and stores type + value.  Credential values are zeroed on
 *   cache eviction and plugin cleanup.
 *
 * Session cookie capture:
 *   When a response arrives with Set-Cookie for a domain that has a
 *   password-type credential, the plugin calls SET_SESSION on vault
 *   to persist the cookies.  On subsequent requests to that domain,
 *   GET_SESSION returns the stored cookies which are injected directly,
 *   bypassing manual login entirely.
 *
 * Config section: [plugin.credinjector]
 *   enabled      = true
 *   socket_path  = ~/.deadlight/vault.sock
 *
 * Note: vault must be running ("vault serve") before the proxy starts,
 * or the plugin will warn and pass requests through unauthenticated.
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/deadlight.h"
#include "credinjector.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Forward declarations
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean injector_init(DeadlightContext *context);
static void     injector_cleanup(DeadlightContext *context);
static gboolean on_request_headers(DeadlightRequest *request);
static gboolean on_response_headers(DeadlightResponse *response);

static gchar       *vault_request(InjectorData *data, const gchar *req);
static CachedCred  *lookup_or_fetch(InjectorData *data, const gchar *domain);
static void         free_cached_cred(gpointer p);
static gchar       *extract_host(const gchar *host_header);
static InjectorCredType parse_cred_type(const gchar *type_str);

/* ─────────────────────────────────────────────────────────────────────────────
 * Vault socket client
 * Mirrors vault_socket_request() from vault_socket.c — kept inline here
 * so the proxy plugin has zero deadvault build dependency.
 * ───────────────────────────────────────────────────────────────────────────*/

static gchar *vault_request(InjectorData *data, const gchar *req)
{
    if (!data->socket_path || !req) return NULL;

    const gchar *path = data->socket_path;

    /* Expand ~ manually — GLib's g_build_filename doesn't expand ~ */
    gchar *expanded = NULL;
    if (path[0] == '~') {
        const gchar *home = g_get_home_dir();
        expanded = g_strconcat(home, path + 1, NULL);
        path = expanded;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        g_free(expanded);
        data->vault_errors++;
        return NULL;
    }

    /* Read/write timeout */
    struct timeval tv = { .tv_sec = INJECTOR_SOCKET_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
    g_free(expanded);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        data->vault_errors++;
        return NULL;
    }

    /* Send request + newline */
    gsize req_len = strlen(req);
    gssize written = 0;
    while ((gsize)written < req_len) {
        gssize n = write(fd, req + written, req_len - (gsize)written);
        if (n <= 0) { close(fd); data->vault_errors++; return NULL; }
        written += n;
    }
    write(fd, "\n", 1);

    /* Read response line */
    gchar  *resp = g_malloc(INJECTOR_MAX_RESPONSE);
    gsize   pos  = 0;

    while (pos < (gsize)INJECTOR_MAX_RESPONSE - 1) {
        gssize n = read(fd, resp + pos, 1);
        if (n <= 0) break;
        if (resp[pos] == '\n') { pos++; break; }
        pos++;
    }
    resp[pos] = '\0';
    close(fd);
    data->vault_queries++;

    /* Trim trailing whitespace */
    while (pos > 0 && (resp[pos-1] == '\n' || resp[pos-1] == '\r'))
        resp[--pos] = '\0';

    return resp;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Utilities
 * ───────────────────────────────────────────────────────────────────────────*/

static InjectorCredType parse_cred_type(const gchar *s)
{
    if (!s) return CRED_TYPE_UNKNOWN;
    if (g_strcmp0(s, "token")    == 0) return CRED_TYPE_TOKEN;
    if (g_strcmp0(s, "password") == 0) return CRED_TYPE_PASSWORD;
    if (g_strcmp0(s, "ssh_key")  == 0) return CRED_TYPE_SSH_KEY;
    return CRED_TYPE_UNKNOWN;
}

static void free_cached_cred(gpointer p)
{
    CachedCred *c = (CachedCred *)p;
    if (!c) return;
    g_free(c->domain);
    g_free(c->cred_name);
    if (c->value) {
        /* Zero credential material before freeing */
        memset(c->value, 0, c->value_len);
        g_free(c->value);
    }
    g_free(c);
}

/**
 * Strip port from a Host header value.
 * "api.github.com:443" → "api.github.com"
 * Returns a heap-allocated string; caller must g_free.
 */
static gchar *extract_host(const gchar *host_header)
{
    if (!host_header) return NULL;
    const gchar *colon = strrchr(host_header, ':');
    if (colon) {
        /* Make sure it's a port (all digits after colon) */
        gboolean is_port = TRUE;
        for (const gchar *p = colon + 1; *p; p++) {
            if (*p < '0' || *p > '9') { is_port = FALSE; break; }
        }
        if (is_port)
            return g_strndup(host_header, (gsize)(colon - host_header));
    }
    return g_strdup(host_header);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Credential cache lookup / vault fetch
 * ───────────────────────────────────────────────────────────────────────────*/

/**
 * Return a CachedCred for the given domain, fetching from vault if needed.
 * Returns NULL if vault has no matching credential or is unreachable.
 * The returned pointer is owned by the cache; do not free it.
 */
static CachedCred *lookup_or_fetch(InjectorData *data, const gchar *domain)
{
    /* Fast path: known miss */
    if (g_hash_table_contains(data->no_cred_domains, domain))
        return NULL;

    /* Fast path: cached hit */
    CachedCred *cached = g_hash_table_lookup(data->cred_cache, domain);
    if (cached) {
        data->cache_hits++;
        return cached;
    }

    /* Ask vault: GET_CREDENTIAL <domain>
     * Vault stores the proxy_match in metadata; we query by domain name
     * directly because the credential NAME is typically the domain or a
     * human alias.  If the user named the credential differently, they
     * can set proxy_match in metadata and we'd need a lookup-by-domain
     * endpoint — defer that to a future vault command.
     * For now: credential name == domain is the convention.              */
    gchar *req  = g_strdup_printf("GET_CREDENTIAL %s", domain);
    gchar *resp = vault_request(data, req);
    g_free(req);

    if (!resp) {
        /* Vault unreachable — don't cache miss so we retry next request */
        return NULL;
    }

    if (!g_str_has_prefix(resp, "OK ")) {
        /* Vault said NOT_FOUND or LOCKED */
        g_free(resp);
        g_hash_table_add(data->no_cred_domains, g_strdup(domain));
        return NULL;
    }

    /* Parse "OK <type> <value>" */
    gchar **parts = g_strsplit(resp + 3, " ", 2);
    g_free(resp);

    if (!parts[0] || !parts[1]) {
        g_strfreev(parts);
        g_hash_table_add(data->no_cred_domains, g_strdup(domain));
        return NULL;
    }

    CachedCred *cred = g_new0(CachedCred, 1);
    cred->domain     = g_strdup(domain);
    cred->cred_name  = g_strdup(domain);   /* same convention */
    cred->type       = parse_cred_type(parts[0]);
    cred->value      = g_strdup(parts[1]);
    cred->value_len  = strlen(parts[1]);

    /* Zero the parts array's value slot before freeing */
    memset(parts[1], 0, cred->value_len);
    g_strfreev(parts);

    if (cred->type == CRED_TYPE_UNKNOWN || cred->type == CRED_TYPE_SSH_KEY) {
        free_cached_cred(cred);
        g_hash_table_add(data->no_cred_domains, g_strdup(domain));
        return NULL;
    }

    /* Evict oldest entry if cache is full */
    if (g_hash_table_size(data->cred_cache) >= INJECTOR_CACHE_MAX) {
        /* Simple strategy: clear the whole cache — domains will re-populate */
        g_warning("credinjector: credential cache full, flushing");
        g_hash_table_remove_all(data->cred_cache);
    }

    g_hash_table_insert(data->cred_cache, g_strdup(domain), cred);
    return cred;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Plugin lifecycle
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean injector_init(DeadlightContext *context)
{
    g_info("CredInjector: initializing...");

    InjectorData *data = g_new0(InjectorData, 1);

    data->enabled     = deadlight_config_get_bool(context, "plugin.credinjector",
                                                  "enabled", TRUE);
    data->socket_path = deadlight_config_get_string(context, "plugin.credinjector",
                                                    "socket_path",
                                                    "~/.deadlight/vault.sock");

    data->cred_cache      = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, free_cached_cred);
    data->no_cred_domains = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, NULL);

    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                      g_free, NULL);
    }
    g_hash_table_insert(context->plugins_data, g_strdup("credinjector"), data);

    /* Quick connectivity test — warn but don't fail init */
    gchar *ping = vault_request(data, "GET_CREDENTIAL __ping__");
    if (!ping) {
        g_warning("CredInjector: vault socket not reachable at %s — "
                  "requests will pass through unauthenticated until vault serves",
                  data->socket_path);
    } else {
        g_info("CredInjector: vault socket reachable");
        g_free(ping);
    }

    g_info("CredInjector: ready");
    return TRUE;
}

static void injector_cleanup(DeadlightContext *context)
{
    if (!context->plugins_data) return;

    InjectorData *data = g_hash_table_lookup(context->plugins_data,
                                              "credinjector");
    if (!data) return;

    g_info("CredInjector stats: injected_token=%lu injected_session=%lu "
           "cache_hits=%lu vault_queries=%lu vault_errors=%lu",
           data->injected_token, data->injected_session,
           data->cache_hits, data->vault_queries, data->vault_errors);

    g_hash_table_destroy(data->cred_cache);
    g_hash_table_destroy(data->no_cred_domains);
    g_free(data->socket_path);
    g_free(data);

    g_hash_table_remove(context->plugins_data, "credinjector");
}

/* ─────────────────────────────────────────────────────────────────────────────
 * on_request_headers — main injection hook
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean on_request_headers(DeadlightRequest *request)
{
    if (!request || !request->connection || !request->connection->context)
        return TRUE;

    InjectorData *data = g_hash_table_lookup(
        request->connection->context->plugins_data, "credinjector");
    if (!data || !data->enabled) return TRUE;

    /* Determine the effective host */
    const gchar *host_raw = request->host;
    if (!host_raw)
        host_raw = g_hash_table_lookup(request->headers, "Host");
    if (!host_raw) return TRUE;

    gchar *host = extract_host(host_raw);
    if (!host) return TRUE;

    /* ── Try session cookie first (cheapest, avoids credential exposure) ── */
    {
        gchar *req  = g_strdup_printf("GET_SESSION %s", host);
        gchar *resp = vault_request(data, req);
        g_free(req);

        if (resp && g_str_has_prefix(resp, "OK ")) {
            /* Parse "OK <expires_at> <cookies_json>" */
            const gchar *after_ok = resp + 3;
            const gchar *space    = strchr(after_ok, ' ');

            if (space) {
                const gchar *cookies_json = space + 1;

                /* cookies_json is a JSON array:
                 * [{"name":"session","value":"abc","path":"/"}]
                 * Build a Cookie: header value from it.
                 * Full JSON parse would need json-glib; we do a lightweight
                 * scan for "name":"..." and "value":"..." pairs instead.   */

                GString *cookie_header = g_string_new(NULL);
                const gchar *p = cookies_json;
                gboolean first = TRUE;

                while ((p = strstr(p, "\"name\"")) != NULL) {
                    /* Extract name value */
                    const gchar *name_start = strchr(p + 6, '"');
                    if (!name_start) break;
                    name_start++;
                    const gchar *name_end = strchr(name_start, '"');
                    if (!name_end) break;
                    gchar *cname = g_strndup(name_start,
                                             (gsize)(name_end - name_start));

                    /* Find matching value field */
                    const gchar *val_key = strstr(name_end, "\"value\"");
                    const gchar *cvalue  = NULL;
                    gchar *cval_str      = NULL;

                    if (val_key) {
                        const gchar *vs = strchr(val_key + 7, '"');
                        if (vs) {
                            vs++;
                            const gchar *ve = strchr(vs, '"');
                            if (ve) {
                                cval_str = g_strndup(vs, (gsize)(ve - vs));
                                cvalue   = cval_str;
                            }
                        }
                    }

                    if (cname && cvalue) {
                        if (!first) g_string_append(cookie_header, "; ");
                        g_string_append_printf(cookie_header, "%s=%s",
                                               cname, cvalue);
                        first = FALSE;
                    }

                    g_free(cname);
                    g_free(cval_str);
                    p = name_end + 1;
                }

                if (cookie_header->len > 0) {
                    deadlight_request_set_header(request, "Cookie",
                                                 cookie_header->str);
                    g_debug("CredInjector: injected session cookie for %s", host);
                    data->injected_session++;
                }

                g_string_free(cookie_header, TRUE);
            }

            g_free(resp);
            g_free(host);
            return TRUE;
        }
        g_free(resp);
    }

    /* ── No live session — look up credential ─────────────────────────── */
    CachedCred *cred = lookup_or_fetch(data, host);
    if (!cred) {
        g_free(host);
        return TRUE;   /* no credential for this domain, pass through */
    }

    switch (cred->type) {

    case CRED_TYPE_TOKEN: {
        gchar *header_val = g_strdup_printf("Bearer %s", cred->value);
        deadlight_request_set_header(request, "Authorization", header_val);
        /* Zero token from the format buffer before freeing */
        memset(header_val, 0, strlen(header_val));
        g_free(header_val);
        g_debug("CredInjector: injected Bearer token for %s", host);
        data->injected_token++;
        break;
    }

    case CRED_TYPE_PASSWORD:
        /* Password credentials are handled via session cookies.
         * If we reach here there is no live session — mark the domain
         * so on_response_headers knows to capture Set-Cookie.          */
        g_debug("CredInjector: no session for password domain %s — "
                "will capture cookies on login response", host);
        cred->has_session = FALSE;
        break;

    default:
        break;
    }

    g_free(host);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * on_response_headers — session cookie capture
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean on_response_headers(DeadlightResponse *response)
{
    if (!response || !response->connection || !response->connection->context)
        return TRUE;

    InjectorData *data = g_hash_table_lookup(
        response->connection->context->plugins_data, "credinjector");
    if (!data || !data->enabled) return TRUE;

    /* Only interested in responses that carry Set-Cookie */
    const gchar *set_cookie = g_hash_table_lookup(response->headers,
                                                   "Set-Cookie");
    if (!set_cookie) return TRUE;

    /* Get the target host from the connection */
    const gchar *target = response->connection->target_host;
    if (!target) return TRUE;

    gchar *host = extract_host(target);
    if (!host) return TRUE;

    /* Only capture for domains with a password-type credential */
    CachedCred *cred = g_hash_table_lookup(data->cred_cache, host);
    if (!cred || cred->type != CRED_TYPE_PASSWORD) {
        g_free(host);
        return TRUE;
    }

    /* Build a minimal JSON array from the Set-Cookie header.
     * A full cookie jar would parse Max-Age, Path, Domain, Secure, HttpOnly.
     * We capture name=value and expires (if present) for the MVP.          */

    /* Set-Cookie: name=value; Path=/; Expires=...; HttpOnly */
    gchar **attrs = g_strsplit(set_cookie, ";", -1);
    if (!attrs || !attrs[0]) {
        g_strfreev(attrs);
        g_free(host);
        return TRUE;
    }

    /* First token is name=value */
    gchar *eq = strchr(attrs[0], '=');
    if (!eq) {
        g_strfreev(attrs);
        g_free(host);
        return TRUE;
    }

    gchar *cname  = g_strndup(g_strstrip(attrs[0]),
                               (gsize)(eq - attrs[0]));
    gchar *cvalue = g_strdup(g_strstrip(eq + 1));

    /* Look for Expires= attribute */
    gchar *expires_str = NULL;
    gint64 expires_at  = 0;

    for (gint i = 1; attrs[i]; i++) {
        gchar *attr = g_strstrip(attrs[i]);
        if (g_ascii_strncasecmp(attr, "expires=", 8) == 0) {
            expires_str = attr + 8;
            /* Parse HTTP date — approximate: use strptime if available */
            struct tm tm_val;
            memset(&tm_val, 0, sizeof(tm_val));
#ifdef _GNU_SOURCE
            if (strptime(expires_str, "%a, %d %b %Y %H:%M:%S %Z", &tm_val)) {
                expires_at = (gint64)timegm(&tm_val);
            }
#else
            /* Fallback: no expiry parsed, leave as 0 (no known expiry) */
            (void)expires_str;
#endif
            break;
        }
    }

    g_strfreev(attrs);

    /* Build JSON: [{"name":"...","value":"..."}] */
    gchar *cookies_json = g_strdup_printf(
        "[{\"name\":\"%s\",\"value\":\"%s\"}]", cname, cvalue);

    /* Get the User-Agent from the original request if available */
    const gchar *ua = "";
    if (response->connection->current_request) {
        const gchar *ua_hdr = g_hash_table_lookup(
            response->connection->current_request->headers, "User-Agent");
        if (ua_hdr) ua = ua_hdr;
    }

    /* SET_SESSION <domain> <cred_name> <expires_at> <user_agent> <cookies_json> */
    gchar *req = g_strdup_printf("SET_SESSION %s %s %lld %s %s",
                                 host,
                                 cred->cred_name,
                                 (long long)expires_at,
                                 ua[0] ? ua : "unknown",
                                 cookies_json);

    gchar *resp = vault_request(data, req);

    if (resp && g_str_has_prefix(resp, "OK")) {
        g_info("CredInjector: session captured for %s → vault", host);
        cred->has_session = TRUE;
        /* Flush the no_cred_domains negative cache entry if present,
         * so next request picks up the session.                        */
        g_hash_table_remove(data->no_cred_domains, host);
    } else {
        g_warning("CredInjector: failed to persist session for %s: %s",
                  host, resp ? resp : "(no response)");
    }

    g_free(resp);
    g_free(req);
    g_free(cookies_json);
    g_free(cname);
    g_free(cvalue);
    g_free(host);

    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Plugin loader entry point
 * ───────────────────────────────────────────────────────────────────────────*/

static DeadlightPlugin credinjector_plugin = {
    .name                = "CredInjector",
    .version             = "1.0.0",
    .description         = "Injects credentials from deadvault into proxied requests",
    .author              = "gnarzilla",
    .init                = injector_init,
    .cleanup             = injector_cleanup,
    .on_request_headers  = on_request_headers,
    .on_response_headers = on_response_headers,
    .on_response_body    = NULL,
    .on_connection_accept   = NULL,
    .on_protocol_detect     = NULL,
    .on_connection_close    = NULL,
    .on_config_change       = NULL,
    .private_data           = NULL,
    .ref_count              = 1
};

G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin)
{
    *plugin = &credinjector_plugin;
    return TRUE;
}
