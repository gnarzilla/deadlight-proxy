/**
 * Deadlight Proxy - Ad Blocker Plugin
 *
 * Blocks ads and trackers at the proxy layer via:
 *   - Domain blocking (request headers / CONNECT)
 *   - URL pattern matching
 *   - HTML content filtering (<script src=...> and <img src=...>)
 *
 * Config section: [plugin.adblocker]
 *   enabled          = true
 *   blocklist_url    = https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
 *   blocklist_file   = /var/cache/deadlight/blocklist.txt
 *   update_interval  = 86400
 *   custom_rules     =
 */

#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <string.h>
#include "core/deadlight.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Data structures
 * ───────────────────────────────────────────────────────────────────────────*/

typedef struct {
    GHashTable *blocked_domains;   /* exact + parent-domain matches           */
    GHashTable *blocked_keywords;  /* substring matches against domain        */
    GRegex    **blocked_patterns;  /* compiled regex set for URL patterns     */
    gint        pattern_count;
    gboolean    enabled;

    /* statistics */
    guint64 requests_blocked;
    guint64 requests_allowed;
    guint64 bytes_saved;           /* bytes of HTML content removed           */

    /* config */
    gchar  *blocklist_url;
    gchar  *blocklist_file;        /* on-disk cache of the remote list        */
    gchar **custom_rules;          /* NULL-terminated array of extra domains  */
    guint   update_interval;       /* seconds between refreshes               */

    /* update timer */
    guint update_source_id;
} AdBlockerData;

/* ─────────────────────────────────────────────────────────────────────────────
 * Forward declarations
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean adblocker_init(DeadlightContext *context);
static void     adblocker_cleanup(DeadlightContext *context);
static gboolean on_request_headers(DeadlightRequest *request);
static gboolean on_response_headers(DeadlightResponse *response);
static gboolean on_response_body(DeadlightResponse *response);

static gboolean load_blocklist_file(AdBlockerData *data);
static gboolean fetch_and_cache_blocklist(AdBlockerData *data);
static gboolean update_blocklists(gpointer user_data);
static gboolean is_blocked_domain(AdBlockerData *data, const gchar *domain);
static gboolean is_blocked_url(AdBlockerData *data, const gchar *url);
static void     send_blocked_response(DeadlightRequest *request,
                                      const gchar *response_str);

/* ─────────────────────────────────────────────────────────────────────────────
 * Helpers
 * ───────────────────────────────────────────────────────────────────────────*/

/**
 * Parse a single line from a hosts-format blocklist and insert the domain
 * into the hash table if it represents a blocked entry.
 *
 * Handles:
 *   0.0.0.0 ads.example.com     <- hosts format, blocked
 *   127.0.0.1 ads.example.com   <- hosts format, blocked
 *   ads.example.com             <- plain domain format
 *   # comment                   <- ignored
 */
static void parse_blocklist_line(const gchar *line, GHashTable *blocked_domains,
                                 gint *count)
{
    if (!line || line[0] == '#' || line[0] == '\0') return;

    gchar **parts = g_strsplit_set(line, " \t", 3);

    if (parts[0] && parts[1]) {
        /* hosts-format: IP  domain  [optional comment] */
        if (g_strcmp0(parts[0], "0.0.0.0")   == 0 ||
            g_strcmp0(parts[0], "127.0.0.1") == 0)
        {
            /* skip localhost itself */
            if (g_strcmp0(parts[1], "localhost")       != 0 &&
                g_strcmp0(parts[1], "localhost.local") != 0 &&
                g_strcmp0(parts[1], "broadcasthost")   != 0)
            {
                if (!g_hash_table_contains(blocked_domains, parts[1])) {
                    g_hash_table_insert(blocked_domains,
                                        g_strdup(parts[1]),
                                        GINT_TO_POINTER(1));
                    (*count)++;
                }
            }
        }
    } else if (parts[0] && strchr(parts[0], '.')) {
        /* plain domain line */
        if (!g_hash_table_contains(blocked_domains, parts[0])) {
            g_hash_table_insert(blocked_domains,
                                g_strdup(parts[0]),
                                GINT_TO_POINTER(1));
            (*count)++;
        }
    }

    g_strfreev(parts);
}

/**
 * Load the cached blocklist file into memory.
 * Returns TRUE if at least some entries were loaded.
 */
static gboolean load_blocklist_file(AdBlockerData *data)
{
    if (!data->blocklist_file ||
        !g_file_test(data->blocklist_file, G_FILE_TEST_EXISTS))
    {
        return FALSE;
    }

    g_info("AdBlocker: loading cached blocklist from %s", data->blocklist_file);

    gchar  *content = NULL;
    gsize   length;
    GError *error = NULL;
    gint    count = 0;

    if (!g_file_get_contents(data->blocklist_file, &content, &length, &error)) {
        g_warning("AdBlocker: failed to read %s: %s",
                  data->blocklist_file, error->message);
        g_error_free(error);
        return FALSE;
    }

    gchar **lines = g_strsplit(content, "\n", -1);
    g_free(content);

    for (gint i = 0; lines[i]; i++) {
        gchar *line = g_strstrip(lines[i]);
        parse_blocklist_line(line, data->blocked_domains, &count);
    }
    g_strfreev(lines);

    g_info("AdBlocker: loaded %d entries from cache", count);
    return count > 0;
}

/**
 * Download the remote blocklist via libsoup-2.4, write it to the cache file,
 * then reload.  Called on init and on the update timer.
 *
 * SoupSession is synchronous here — this runs on the GLib thread pool during
 * init, so blocking is fine.  The update timer callback also runs on the main
 * loop thread; for a ~2 MB download over a fast link that's acceptable.  If
 * you want to move this async later, SoupSession has an async API.
 */
static gboolean fetch_and_cache_blocklist(AdBlockerData *data)
{
    if (!data->blocklist_url || data->blocklist_url[0] == '\0') {
        g_debug("AdBlocker: no blocklist_url configured, skipping fetch");
        return FALSE;
    }

    g_info("AdBlocker: fetching blocklist from %s", data->blocklist_url);

    SoupSession *session = soup_session_new_with_options(
        SOUP_SESSION_USER_AGENT, "deadlight-proxy/adblocker",
        SOUP_SESSION_TIMEOUT,    30,
        NULL);

    SoupMessage *msg = soup_message_new("GET", data->blocklist_url);
    if (!msg) {
        g_warning("AdBlocker: invalid blocklist_url: %s", data->blocklist_url);
        g_object_unref(session);
        return FALSE;
    }

    guint status = soup_session_send_message(session, msg);

    if (!SOUP_STATUS_IS_SUCCESSFUL(status)) {
        g_warning("AdBlocker: fetch failed: %u %s", status,
                  soup_status_get_phrase(status));
        g_object_unref(msg);
        g_object_unref(session);
        return FALSE;
    }

    SoupMessageBody *body = msg->response_body;
    soup_message_body_flatten(body);   /* ensure contiguous */

    GString *buf = g_string_new_len(body->data, (gssize)body->length);

    g_object_unref(msg);
    g_object_unref(session);

    /* Ensure the cache directory exists */
    GError *error = NULL;
    if (data->blocklist_file) {
        gchar *dir = g_path_get_dirname(data->blocklist_file);
        g_mkdir_with_parents(dir, 0755);
        g_free(dir);

        if (!g_file_set_contents(data->blocklist_file, buf->str, buf->len, &error)) {
            g_warning("AdBlocker: failed to write cache %s: %s",
                      data->blocklist_file, error->message);
            g_error_free(error);
            /* non-fatal — we still have the content in memory */
        } else {
            g_info("AdBlocker: blocklist cached to %s (%zu bytes)",
                   data->blocklist_file, buf->len);
        }
    }

    /* Parse directly from the in-memory buffer */
    gint count = 0;

    /* Clear stale entries before reload */
    g_hash_table_remove_all(data->blocked_domains);

    gchar **lines = g_strsplit(buf->str, "\n", -1);
    g_string_free(buf, TRUE);

    for (gint i = 0; lines[i]; i++) {
        gchar *line = g_strstrip(lines[i]);
        parse_blocklist_line(line, data->blocked_domains, &count);
    }
    g_strfreev(lines);

    /* Re-apply custom rules after reload */
    if (data->custom_rules) {
        for (gint i = 0; data->custom_rules[i]; i++) {
            const gchar *rule = g_strstrip(data->custom_rules[i]);
            if (rule[0] && rule[0] != '#') {
                if (!g_hash_table_contains(data->blocked_domains, rule)) {
                    g_hash_table_insert(data->blocked_domains,
                                        g_strdup(rule),
                                        GINT_TO_POINTER(1));
                    count++;
                }
            }
        }
    }

    g_info("AdBlocker: loaded %d domains from remote list", count);
    return count > 0;
}

/**
 * Timer callback — re-fetch and reload.
 */
static gboolean update_blocklists(gpointer user_data)
{
    AdBlockerData *data = (AdBlockerData *)user_data;
    g_info("AdBlocker: scheduled update triggered");
    fetch_and_cache_blocklist(data);
    return G_SOURCE_CONTINUE;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Domain / URL matching
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean is_blocked_domain(AdBlockerData *data, const gchar *domain)
{
    if (!domain) return FALSE;

    /* Exact match */
    if (g_hash_table_contains(data->blocked_domains, domain))
        return TRUE;

    /* Walk up parent domains: "ads.sub.example.com" → "sub.example.com"
     * → "example.com".  Stops before the TLD-only token.                  */
    const gchar *dot = strchr(domain, '.');
    while (dot && strchr(dot + 1, '.')) {   /* require at least one more dot */
        dot++;
        if (g_hash_table_contains(data->blocked_domains, dot))
            return TRUE;
        dot = strchr(dot, '.');
    }

    /* Keyword scan */
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, data->blocked_keywords);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        if (strstr(domain, (gchar *)key))
            return TRUE;
    }

    return FALSE;
}

static gboolean is_blocked_url(AdBlockerData *data, const gchar *url)
{
    if (!url) return FALSE;

    /* Regex patterns (loaded from config, if any) */
    for (gint i = 0; i < data->pattern_count; i++) {
        if (data->blocked_patterns[i] &&
            g_regex_match(data->blocked_patterns[i], url, 0, NULL))
            return TRUE;
    }

    /* Common ad/tracker URL path segments */
    static const gchar *ad_path_segments[] = {
        "/doubleclick/", "/googleads/", "/adsense/", "/adserver/",
        "/advertisement/", "/analytics/", "/tracking/", "/beacon/",
        "/telemetry/", "/pixel/", "/impression/",
        NULL
    };
    for (gint i = 0; ad_path_segments[i]; i++) {
        if (strstr(url, ad_path_segments[i]))
            return TRUE;
    }

    /* Query-string signals */
    if (strstr(url, "?utm_") || strstr(url, "&utm_"))
        return FALSE;   /* UTM params alone don't block, just strip in future */

    return FALSE;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HTML content filtering
 * ───────────────────────────────────────────────────────────────────────────*/

/**
 * Walk `html` (in-place, NUL-terminated) and remove any <script src="...">
 * or <img src="..."> tag whose src attribute resolves to a blocked domain.
 *
 * Strategy: scan for src=" or src=', extract the value, check the host
 * portion against is_blocked_domain(), and if blocked replace the entire
 * enclosing tag with spaces (preserving byte offsets so we don't have to
 * re-allocate).  bytes_removed is incremented by the tag length.
 *
 * Returns the number of bytes removed (tags overwritten with spaces).
 */
static gsize filter_html_content(AdBlockerData *data, gchar *html, gsize length)
{
    gsize removed = 0;

    /* We need a writable, NUL-terminated buffer — callers must ensure this. */

    gchar *pos = html;
    gchar *end = html + length;

    while (pos < end) {
        /* Find the next opening tag that could carry a src= */
        gchar *tag_open = memchr(pos, '<', (size_t)(end - pos));
        if (!tag_open) break;

        /* Only process <script and <img tags */
        gboolean is_script = (g_ascii_strncasecmp(tag_open, "<script", 7) == 0);
        gboolean is_img    = (g_ascii_strncasecmp(tag_open, "<img",    4) == 0);

        if (!is_script && !is_img) {
            pos = tag_open + 1;
            continue;
        }

        /* Find the closing > of this tag.
         * For <script> we want the whole </script> block; for <img> just the
         * self-closing tag.  Keep it simple: find the tag's own closing >.  */
        gchar *tag_close = memchr(tag_open + 1, '>', (size_t)(end - tag_open - 1));
        if (!tag_close) {
            pos = tag_open + 1;
            continue;
        }

        /* Locate src= within the tag */
        gsize  tag_header_len = (gsize)(tag_close - tag_open) + 1;
        gchar *src_attr = g_strstr_len(tag_open,
                                       (gssize)tag_header_len,
                                       "src=");
        if (!src_attr) {
            pos = tag_close + 1;
            continue;
        }

        /* Extract the src value */
        gchar quote = src_attr[4];
        if (quote != '"' && quote != '\'') {
            pos = tag_close + 1;
            continue;
        }

        gchar *val_start = src_attr + 5;
        gchar *val_end   = memchr(val_start, quote, (size_t)(tag_close - val_start + 1));
        if (!val_end) {
            pos = tag_close + 1;
            continue;
        }

        gchar *src_value = g_strndup(val_start, (gsize)(val_end - val_start));

        /* Pull hostname from the src URL */
        gchar *host = NULL;
        if (g_str_has_prefix(src_value, "http://") ||
            g_str_has_prefix(src_value, "https://"))
        {
            const gchar *after_scheme = strstr(src_value, "//") + 2;
            const gchar *host_end     = strpbrk(after_scheme, "/:?#");
            host = host_end
                   ? g_strndup(after_scheme, (gsize)(host_end - after_scheme))
                   : g_strdup(after_scheme);
        } else if (src_value[0] == '/' || src_value[0] == '.') {
            /* relative URL — can't block by host */
        } else {
            /* protocol-relative //host/... */
            if (g_str_has_prefix(src_value, "//")) {
                const gchar *after = src_value + 2;
                const gchar *he    = strpbrk(after, "/:?#");
                host = he ? g_strndup(after, (gsize)(he - after)) : g_strdup(after);
            }
        }

        g_free(src_value);

        if (host && is_blocked_domain(data, host)) {
            /* For <script> tags, also consume the </script> block */
            gchar *erase_start = tag_open;
            gchar *erase_end   = tag_close + 1;

            if (is_script) {
                /* Find </script> after the opening tag */
                gchar *close_tag = g_strstr_len(
                    tag_close + 1,
                    (gssize)(end - tag_close - 1),
                    "</script>");
                if (close_tag) {
                    erase_end = close_tag + 9; /* len("</script>") == 9 */
                }
            }

            gsize erase_len = (gsize)(erase_end - erase_start);
            g_debug("AdBlocker: filtering <%s src=...> for host %s (%zu bytes)",
                    is_script ? "script" : "img", host, erase_len);

            memset(erase_start, ' ', erase_len);
            removed += erase_len;

            pos = erase_end;
        } else {
            pos = tag_close + 1;
        }

        g_free(host);
    }

    return removed;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Shared helper: write a canned HTTP response to the client
 * ───────────────────────────────────────────────────────────────────────────*/

static void send_blocked_response(DeadlightRequest *request,
                                  const gchar *response_str)
{
    GOutputStream *output = g_io_stream_get_output_stream(
        G_IO_STREAM(request->connection->client_connection));
    g_output_stream_write(output, response_str, strlen(response_str), NULL, NULL);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Plugin lifecycle
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean adblocker_init(DeadlightContext *context)
{
    g_info("AdBlocker: initializing...");

    AdBlockerData *data = g_new0(AdBlockerData, 1);

    data->enabled = deadlight_config_get_bool(context, "plugin.adblocker",
                                              "enabled", TRUE);

    data->blocked_domains  = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, NULL);
    data->blocked_keywords = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, NULL);

    /* Config */
    data->blocklist_url  = deadlight_config_get_string(context, "plugin.adblocker",
                                                       "blocklist_url", "");
    data->blocklist_file = deadlight_config_get_string(context, "plugin.adblocker",
                                                       "blocklist_file",
                                                       "/var/cache/deadlight/blocklist.txt");
    data->update_interval = (guint)deadlight_config_get_int(context, "plugin.adblocker",
                                                            "update_interval", 86400);

    /* Custom rules: comma- or newline-separated domain list */
    gchar *custom_raw = deadlight_config_get_string(context, "plugin.adblocker",
                                                    "custom_rules", "");
    if (custom_raw && custom_raw[0]) {
        data->custom_rules = g_strsplit_set(custom_raw, ",\n", -1);
    }
    g_free(custom_raw);

    /* No regex patterns wired up from config yet; slot is here for future use */
    data->blocked_patterns = NULL;
    data->pattern_count    = 0;

    /* Bootstrap: try cache first so we're not blocking startup on a network
     * fetch, then always do a fresh fetch in the background.               */
    load_blocklist_file(data);

    /* Apply custom rules on top of whatever the cache gave us */
    if (data->custom_rules) {
        for (gint i = 0; data->custom_rules[i]; i++) {
            gchar *rule = g_strstrip(data->custom_rules[i]);
            if (rule[0] && rule[0] != '#') {
                if (!g_hash_table_contains(data->blocked_domains, rule)) {
                    g_hash_table_insert(data->blocked_domains,
                                        g_strdup(rule), GINT_TO_POINTER(1));
                }
            }
        }
    }

    /* Fresh fetch — overwrites cache, clears + repopulates blocked_domains */
    fetch_and_cache_blocklist(data);

    /* Periodic refresh */
    if (data->update_interval > 0) {
        data->update_source_id = g_timeout_add_seconds(data->update_interval,
                                                       update_blocklists, data);
    }

    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                      g_free, NULL);
    }
    g_hash_table_insert(context->plugins_data, g_strdup("adblocker"), data);

    g_info("AdBlocker: ready — %u domains blocked",
           g_hash_table_size(data->blocked_domains));
    return TRUE;
}

static void adblocker_cleanup(DeadlightContext *context)
{
    if (!context->plugins_data) return;

    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return;

    g_info("AdBlocker stats: blocked=%lu  allowed=%lu  html_bytes_removed=%lu",
           data->requests_blocked, data->requests_allowed, data->bytes_saved);

    if (data->update_source_id)
        g_source_remove(data->update_source_id);

    g_hash_table_destroy(data->blocked_domains);
    g_hash_table_destroy(data->blocked_keywords);

    if (data->blocked_patterns) {
        for (gint i = 0; i < data->pattern_count; i++) {
            if (data->blocked_patterns[i])
                g_regex_unref(data->blocked_patterns[i]);
        }
        g_free(data->blocked_patterns);
    }

    g_free(data->blocklist_url);
    g_free(data->blocklist_file);
    g_strfreev(data->custom_rules);
    g_free(data);

    /* Remove the (now-dangling) pointer from the table */
    g_hash_table_remove(context->plugins_data, "adblocker");
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Plugin hooks
 * ───────────────────────────────────────────────────────────────────────────*/

static gboolean on_request_headers(DeadlightRequest *request)
{
    if (!request || !request->connection || !request->connection->context)
        return TRUE;

    AdBlockerData *data = g_hash_table_lookup(
        request->connection->context->plugins_data, "adblocker");
    if (!data || !data->enabled) return TRUE;

    /* ── CONNECT tunnel ─────────────────────────────────────────────────── */
    if (g_strcmp0(request->method, "CONNECT") == 0) {
        const gchar *host   = NULL;
        gchar       *extracted = NULL;

        if (request->uri) {
            gchar *colon = strrchr(request->uri, ':');
            if (colon) {
                extracted = g_strndup(request->uri, (gsize)(colon - request->uri));
                host = extracted;
            } else {
                host = request->uri;
            }
        }

        gboolean blocked = host && is_blocked_domain(data, host);
        g_free(extracted);

        if (blocked) {
            g_info("AdBlocker: blocking CONNECT %s", request->uri);
            data->requests_blocked++;
            send_blocked_response(request,
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Length: 0\r\n"
                "X-Blocked-By: Deadlight-AdBlocker\r\n"
                "\r\n");
            return FALSE;
        }

        data->requests_allowed++;
        return TRUE;
    }

    /* ── Plain HTTP request ─────────────────────────────────────────────── */
    const gchar *host = request->host;
    if (!host)
        host = g_hash_table_lookup(request->headers, "Host");

    /* Strip port from Host header if present */
    gchar *host_clean = NULL;
    if (host) {
        gchar *colon = strrchr(host, ':');
        if (colon)
            host_clean = g_strndup(host, (gsize)(colon - host));
    }

    const gchar *effective_host = host_clean ? host_clean : host;

    if (effective_host && is_blocked_domain(data, effective_host)) {
        g_info("AdBlocker: blocking HTTP %s %s", request->method, effective_host);
        data->requests_blocked++;
        g_free(host_clean);
        send_blocked_response(request,
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "X-Blocked-By: Deadlight-AdBlocker\r\n"
            "\r\n");
        return FALSE;
    }
    g_free(host_clean);

    /* ── URL pattern check ──────────────────────────────────────────────── */
    if (request->uri && is_blocked_url(data, request->uri)) {
        g_info("AdBlocker: blocking URL pattern %s", request->uri);
        data->requests_blocked++;
        request->blocked      = TRUE;
        request->block_reason = g_strdup("URL pattern blocked by AdBlocker");
        send_blocked_response(request,
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "X-Blocked-By: Deadlight-AdBlocker\r\n"
            "\r\n");
        return FALSE;
    }

    data->requests_allowed++;
    return TRUE;
}

static gboolean on_response_headers(DeadlightResponse *response)
{
    (void)response;
    return TRUE;
}

/**
 * Content filtering: strip <script src="blocked-domain"> and
 * <img src="blocked-domain"> from HTML responses.
 *
 * bytes_saved is incremented by the exact number of bytes overwritten.
 */
static gboolean on_response_body(DeadlightResponse *response)
{
    if (!response || !response->connection || !response->connection->context)
        return TRUE;

    AdBlockerData *data = g_hash_table_lookup(
        response->connection->context->plugins_data, "adblocker");
    if (!data || !data->enabled) return TRUE;

    /* Gate to text/html only */
    const gchar *ct = g_hash_table_lookup(response->headers, "Content-Type");
    if (!ct || !g_strstr_len(ct, (gssize)strlen(ct), "text/html"))
        return TRUE;

    if (!response->body || response->body->len == 0)
        return TRUE;

    /* Ensure the body buffer is NUL-terminated so string functions are safe.
     * GByteArray doesn't guarantee this, so append a NUL without changing len */
    g_byte_array_append(response->body, (const guint8 *)"\0", 1);
    response->body->len--;   /* don't count the sentinel in reported length   */

    gsize removed = filter_html_content(data,
                                        (gchar *)response->body->data,
                                        response->body->len);
    if (removed > 0) {
        data->bytes_saved    += removed;
        response->modified    = TRUE;

        /* Update Content-Length to reflect the new (logically shorter) body.
         * We've overwritten with spaces so byte count is unchanged, but
         * the effective payload shrank — update the header for accuracy.   */
        gchar *new_len = g_strdup_printf("%u", response->body->len);
        g_hash_table_replace(response->headers,
                             g_strdup("Content-Length"), new_len);

        g_debug("AdBlocker: removed %zu bytes of ad content from response",
                removed);
    }

    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public integration API (non-plugin / direct call mode)
 * ───────────────────────────────────────────────────────────────────────────*/

gboolean deadlight_adblocker_init(DeadlightContext *context)
{
    return adblocker_init(context);
}

gboolean deadlight_adblocker_should_block_host(DeadlightContext *context,
                                               const gchar *host)
{
    if (!context || !context->plugins_data) return FALSE;
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return FALSE;
    return is_blocked_domain(data, host);
}

gboolean deadlight_adblocker_should_block_url(DeadlightContext *context,
                                              const gchar *url)
{
    if (!context || !context->plugins_data) return FALSE;
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return FALSE;
    return is_blocked_url(data, url);
}

void deadlight_adblocker_get_stats(DeadlightContext *context,
                                   guint64 *blocked,
                                   guint64 *allowed,
                                   guint64 *bytes_saved)
{
    if (!context || !context->plugins_data) return;
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return;
    if (blocked)     *blocked     = data->requests_blocked;
    if (allowed)     *allowed     = data->requests_allowed;
    if (bytes_saved) *bytes_saved = data->bytes_saved;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Plugin loader entry point
 * ───────────────────────────────────────────────────────────────────────────*/

static DeadlightPlugin adblocker_plugin = {
    .name               = "AdBlocker",
    .version            = "1.1.0",
    .description        = "Blocks ads and trackers at the proxy layer",
    .author             = "Deadlight Team",
    .init               = adblocker_init,
    .cleanup            = adblocker_cleanup,
    .on_request_headers = on_request_headers,
    .on_response_headers= on_response_headers,
    .on_response_body   = on_response_body,
    .on_connection_accept  = NULL,
    .on_protocol_detect    = NULL,
    .on_connection_close   = NULL,
    .on_config_change      = NULL,
    .private_data          = NULL,
    .ref_count             = 1
};

G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin)
{
    *plugin = &adblocker_plugin;
    return TRUE;
}