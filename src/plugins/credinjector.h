// src/plugins/credinjector.h
#ifndef DEADLIGHT_CREDINJECTOR_H
#define DEADLIGHT_CREDINJECTOR_H

#include <glib.h>
#include "core/deadlight.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────────────────────*/

#define INJECTOR_MAX_RESPONSE  65536
#define INJECTOR_CACHE_MAX     256      /* max cached domain→credential entries */
#define INJECTOR_SOCKET_TIMEOUT_SEC 3

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal types
 * ───────────────────────────────────────────────────────────────────────────*/

typedef enum {
    CRED_TYPE_TOKEN    = 0,
    CRED_TYPE_PASSWORD = 1,
    CRED_TYPE_SSH_KEY  = 2,
    CRED_TYPE_UNKNOWN  = 99
} InjectorCredType;

typedef struct {
    gchar           *domain;       /* owned */
    gchar           *cred_name;    /* vault credential name, owned */
    InjectorCredType type;
    gchar           *value;        /* decrypted value, owned, zeroed on free */
    gsize            value_len;
    gboolean         has_session;  /* true if vault has a live session cookie */
} CachedCred;

typedef struct {
    gboolean   enabled;
    gchar     *socket_path;

    /* Domain → CachedCred* hash table.
     * Keys are domain strings (owned by the CachedCred).
     * Values are CachedCred* (freed by free_cached_cred).              */
    GHashTable *cred_cache;

    /* Domains known to have NO vault credential — skip socket round-trip */
    GHashTable *no_cred_domains;

    /* Stats */
    guint64 injected_token;
    guint64 injected_session;
    guint64 cache_hits;
    guint64 vault_queries;
    guint64 vault_errors;
} InjectorData;

static gboolean injector_init(DeadlightContext *context);
static void     injector_cleanup(DeadlightContext *context);
static gboolean on_request_headers(DeadlightRequest *request);
static gboolean on_response_headers(DeadlightResponse *response);

static gchar       *vault_request(InjectorData *data, const gchar *req);
static CachedCred  *lookup_or_fetch(InjectorData *data, const gchar *domain);
static void         free_cached_cred(gpointer p);
static gchar       *extract_host(const gchar *host_header);
static InjectorCredType parse_cred_type(const gchar *type_str);

#endif // DEADLIGHT_CREDINJECTOR_H