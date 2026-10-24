// SPDX-License-Identifier: AGPL-3.0-only
// See core.h for what is ported from console/openpak-nro and what is not.
#include "core.h"
#include "ed25519.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define PLATFORM "switch"

// docs/signed-ceiling.md, "Pinned public key" (same bytes as ceiling.c in the NRO).
static const fd_pinned_key pinned[] = {
    {"36e8bcdd93c2c1a1d7e5d87bbba05a7a4f97882131cf6878f1c053a25a377fe4",
     {0x0f, 0xd2, 0xa2, 0x66, 0x08, 0x68, 0xe5, 0x3d, 0x20, 0xfc, 0x81, 0x1e, 0x3f, 0x15, 0x71, 0x0c,
      0xb1, 0xad, 0x15, 0x7b, 0xa7, 0xda, 0x80, 0x19, 0xf7, 0xa5, 0x9e, 0x8a, 0xd6, 0x04, 0xd8, 0x7c}},
};
const fd_pinned_key *fd_keys = pinned;
int fd_key_count = (int)(sizeof(pinned) / sizeof(*pinned));

static bool fail(char *err, int errlen, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, (size_t)errlen, fmt, ap);
    va_end(ap);
    return false;
}

// ---- a small in-place JSON reader ---------------------------------------------------
// Strict enough for our two documents: objects, arrays, strings (ASCII escapes only),
// integers, true/false/null. Strings are unescaped in place and NUL-terminated, so the
// caller's buffer is consumed. Last duplicate key wins, like json-c.

enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };
#define J_NODES 768
#define J_DEPTH 12
typedef struct {
    unsigned char type, isint;
    int next, child;
    char *key, *str;
    long long num;
} jnode;
static jnode g_nodes[J_NODES];
static int g_nn;

typedef struct { char *p, *end; bool bad; } jp;

static void skip_ws(jp *j) { while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n')) j->p++; }

static char *parse_string(jp *j) {   // j->p at the opening quote
    char *r = j->p + 1, *w = r, *start = r;
    while (r < j->end && *r != '"') {
        unsigned char c = (unsigned char)*r;
        if (c < 0x20) { j->bad = true; return NULL; }
        if (c == '\\') {
            if (++r >= j->end) { j->bad = true; return NULL; }
            switch (*r) {
                case '"': *w++ = '"'; break;
                case '\\': *w++ = '\\'; break;
                case '/': *w++ = '/'; break;
                case 'n': *w++ = '\n'; break;
                case 't': *w++ = '\t'; break;
                case 'r': *w++ = '\r'; break;
                case 'b': *w++ = '\b'; break;
                case 'f': *w++ = '\f'; break;
                case 'u': {
                    if (r + 4 >= j->end) { j->bad = true; return NULL; }
                    unsigned v = 0;
                    for (int i = 1; i <= 4; i++) {
                        char h = r[i];
                        v <<= 4;
                        if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
                        else { j->bad = true; return NULL; }
                    }
                    if (v == 0 || v >= 0x80) { j->bad = true; return NULL; }   // ASCII only
                    *w++ = (char)v;
                    r += 4;
                    break;
                }
                default: j->bad = true; return NULL;
            }
            r++;
        } else {
            *w++ = *r++;
        }
    }
    if (r >= j->end) { j->bad = true; return NULL; }
    *w = '\0';
    j->p = r + 1;
    return start;
}

static int parse_value(jp *j, int depth);

static int new_node(jp *j, int type) {
    if (g_nn >= J_NODES) { j->bad = true; return -1; }
    jnode *n = &g_nodes[g_nn];
    memset(n, 0, sizeof(*n));
    n->type = (unsigned char)type;
    n->next = n->child = -1;
    return g_nn++;
}

static int parse_value(jp *j, int depth) {
    skip_ws(j);
    if (j->bad || j->p >= j->end || depth > J_DEPTH) { j->bad = true; return -1; }
    char c = *j->p;
    if (c == '"') {
        char *s = parse_string(j);
        if (!s) return -1;
        int id = new_node(j, J_STR);
        if (id >= 0) g_nodes[id].str = s;
        return id;
    }
    if (c == '{' || c == '[') {
        bool obj = c == '{';
        char close = obj ? '}' : ']';
        int id = new_node(j, obj ? J_OBJ : J_ARR);
        if (id < 0) return -1;
        j->p++;
        skip_ws(j);
        int last = -1;
        if (j->p < j->end && *j->p == close) { j->p++; return id; }
        for (;;) {
            char *key = NULL;
            skip_ws(j);
            if (obj) {
                if (j->p >= j->end || *j->p != '"') { j->bad = true; return -1; }
                key = parse_string(j);
                if (!key) return -1;
                skip_ws(j);
                if (j->p >= j->end || *j->p++ != ':') { j->bad = true; return -1; }
            }
            int v = parse_value(j, depth + 1);
            if (v < 0) return -1;
            g_nodes[v].key = key;
            if (last < 0) g_nodes[id].child = v; else g_nodes[last].next = v;
            last = v;
            skip_ws(j);
            if (j->p >= j->end) { j->bad = true; return -1; }
            if (*j->p == ',') { j->p++; continue; }
            if (*j->p == close) { j->p++; return id; }
            j->bad = true;
            return -1;
        }
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char *s = j->p;
        if (*s == '-') s++;
        if (s >= j->end || *s < '0' || *s > '9') { j->bad = true; return -1; }
        long long v = 0;
        bool isint = true;
        while (s < j->end && *s >= '0' && *s <= '9') {
            if (v > 922337203685477579LL) { j->bad = true; return -1; }
            v = v * 10 + (*s++ - '0');
        }
        if (s < j->end && (*s == '.' || *s == 'e' || *s == 'E')) {
            isint = false;
            while (s < j->end && (*s == '.' || *s == 'e' || *s == 'E' || *s == '+' || *s == '-' || (*s >= '0' && *s <= '9'))) s++;
        }
        int id = new_node(j, J_NUM);
        if (id < 0) return -1;
        g_nodes[id].num = (*j->p == '-') ? -v : v;
        g_nodes[id].isint = isint;
        j->p = s;
        return id;
    }
    static const struct { const char *w; int type; long long v; } words[] = {
        {"true", J_BOOL, 1}, {"false", J_BOOL, 0}, {"null", J_NULL, 0}};
    for (int i = 0; i < 3; i++) {
        size_t n = strlen(words[i].w);
        if ((size_t)(j->end - j->p) >= n && memcmp(j->p, words[i].w, n) == 0) {
            int id = new_node(j, words[i].type);
            if (id >= 0) g_nodes[id].num = words[i].v;
            j->p += n;
            return id;
        }
    }
    j->bad = true;
    return -1;
}

// Parses the whole buffer as one value; returns the root index or -1.
static int json_parse(char *s, size_t len) {
    g_nn = 0;
    jp j = {s, s + len, false};
    int root = parse_value(&j, 0);
    if (root < 0 || j.bad) return -1;
    skip_ws(&j);
    if (j.p != j.end) return -1;      // trailing garbage
    return root;
}

static int jget(int obj, const char *key) {
    if (obj < 0 || g_nodes[obj].type != J_OBJ) return -1;
    int found = -1;
    for (int c = g_nodes[obj].child; c >= 0; c = g_nodes[c].next)
        if (g_nodes[c].key && strcmp(g_nodes[c].key, key) == 0) found = c;
    return found;
}
static const char *jstr(int obj, const char *key) {
    int v = jget(obj, key);
    return (v >= 0 && g_nodes[v].type == J_STR) ? g_nodes[v].str : NULL;
}
static bool jis(int n, int type) { return n >= 0 && g_nodes[n].type == type; }

// ---- base64 -------------------------------------------------------------------------

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Standard alphabet, padding required (ceiling.c b64decode). Returns the length or -1.
static long b64decode(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s);
    if (n == 0 || n % 4 || n / 4 * 3 > cap) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4];
        for (int k = 0; k < 4; k++) {
            if (s[i + k] == '=' && i + 4 == n && k >= 2) v[k] = -2;
            else if ((v[k] = b64val((unsigned char)s[i + k])) < 0) return -1;
        }
        if (v[2] == -2 && v[3] != -2) return -1;
        out[o++] = (uint8_t)(v[0] << 2 | v[1] >> 4);
        if (v[2] != -2) out[o++] = (uint8_t)((v[1] & 15) << 4 | v[2] >> 2);
        if (v[3] != -2) out[o++] = (uint8_t)((v[2] & 3) << 6 | v[3]);
    }
    return (long)o;
}

// ---- names --------------------------------------------------------------------------

bool fd_family_valid(const char *f) {
    size_t n = strlen(f);
    if (n < 4 || n >= FD_FAMILY_MAX || f[0] != '.') return false;
    int labels = 0;
    const char *p = f + 1;
    while (*p) {
        const char *e = strchr(p, '.');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len == 0 || len > 63 || p[0] == '-' || p[len - 1] == '-') return false;
        for (size_t i = 0; i < len; i++) {
            char c = p[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        }
        labels++;
        p += len + (e ? 1 : 0);
        if (e && !*p) return false;
    }
    return labels >= 2;
}

#define HOST_MAX 160
static bool hostname_valid(const char *h) {
    size_t n = strlen(h);
    if (n == 0 || n >= HOST_MAX - 2 || h[0] == '.' || h[n - 1] == '.') return false;
    for (size_t i = 0; i < n; i++) {
        char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return false;
        if (c == '.' && h[i + 1] == '.') return false;
    }
    return true;
}

static bool ipv4_valid(const char *s) {
    int parts = 0;
    while (parts < 4) {
        int v = 0, digits = 0;
        while (*s >= '0' && *s <= '9' && digits < 4) { v = v * 10 + (*s++ - '0'); digits++; }
        if (digits == 0 || digits > 3 || v > 255) return false;
        parts++;
        if (parts < 4 && *s++ != '.') return false;
    }
    return *s == '\0';
}

bool fd_ip_endpoint_valid(const char *ep) {
    const char *colon = strchr(ep, ':');
    if (!colon || strchr(colon + 1, ':') || colon - ep >= 16) return false;
    char ip[16];
    memcpy(ip, ep, (size_t)(colon - ep));
    ip[colon - ep] = '\0';
    if (!ipv4_valid(ip)) return false;
    for (const char *o = ip; *o; ) {   // no leading zeros: "1.2.3.04" is not an address we sign
        if (o[0] == '0' && o[1] >= '0' && o[1] <= '9') return false;
        while (*o && *o != '.') o++;
        if (*o == '.') o++;
    }
    const char *p = colon + 1;
    long v = 0;
    int digits = 0;
    if (p[0] == '0') return false;
    while (*p >= '0' && *p <= '9' && digits < 6) { v = v * 10 + (*p++ - '0'); digits++; }
    return *p == '\0' && digits > 0 && v >= 1 && v <= 65535;
}

static bool title_valid(const char *t) {
    if (strlen(t) != 16) return false;
    for (; *t; t++)
        if (!((*t >= '0' && *t <= '9') || (*t >= 'a' && *t <= 'f') || (*t >= 'A' && *t <= 'F'))) return false;
    return true;
}

size_t fd_ip_redirects_text(const fd_ceiling *c, char *out, size_t cap) {
    size_t n = 0;
    int written = 0;
    int w = snprintf(out, cap, "# openpak-fetchd: ip redirects from signed ceiling v%lld; do not edit\n", c->version);
    if (w < 0 || (size_t)w >= cap) return 0;
    n = (size_t)w;
    for (int i = 0; i < c->ip_count; i++) {
        const fd_ip_redirect *r = &c->ip[i];
        if (!r->title[0]) continue;
        w = snprintf(out + n, cap - n, "%s %s %s %s\n", r->tcp ? "tcp" : "udp", r->title, r->from, r->to);
        if (w < 0 || (size_t)w >= cap - n) return 0;
        n += (size_t)w;
        written++;
    }
    return written ? n : 0;
}

bool fd_ceiling_covers(const fd_ceiling *c, const char *name) {
    size_t nl = strlen(name);
    for (int i = 0; i < c->count; i++) {
        const char *f = c->families[i];
        size_t fl = strlen(f);
        if (strcmp(name, f + 1) == 0) return true;
        if (nl >= fl && strcmp(name + nl - fl, f) == 0) return true;
    }
    return false;
}

// ---- the signed envelope ------------------------------------------------------------

static uint8_t g_payload[FD_ENVELOPE_MAX / 4 * 3 + 8];

static bool signed_by_pinned_key(int sigs, const uint8_t *payload, size_t plen) {
    for (int s = g_nodes[sigs].child; s >= 0; s = g_nodes[s].next) {
        if (!jis(s, J_OBJ)) continue;
        const char *keyid = jstr(s, "keyid"), *sig64 = jstr(s, "sig");
        if (!keyid || !sig64) continue;
        uint8_t sig[64 + 8];
        long slen = b64decode(sig64, sig, sizeof(sig));
        if (slen != 64) continue;
        for (int k = 0; k < fd_key_count; k++)
            if (strcasecmp(keyid, fd_keys[k].keyid) == 0 &&
                openpak_ed25519_verify(sig, payload, plen, fd_keys[k].pub))
                return true;
    }
    return false;
}

static bool payload_into(int root, fd_ceiling *out, char *err, int errlen) {
    const char *type = jstr(root, "type");
    if (!type || strcmp(type, "openpak-ceiling") != 0) return fail(err, errlen, "not an openpak-ceiling");
    int v = jget(root, "version");
    if (!jis(v, J_NUM) || !g_nodes[v].isint || g_nodes[v].num <= 0)
        return fail(err, errlen, "version is not a positive integer");
    out->version = g_nodes[v].num;
    if (!jstr(root, "issued")) return fail(err, errlen, "no issued time");
    int plats = jget(root, "platforms");
    if (!jis(plats, J_OBJ)) return fail(err, errlen, "no platforms");
    bool mine = false;
    for (int p = g_nodes[plats].child; p >= 0; p = g_nodes[p].next) {
        if (!jis(p, J_ARR)) return fail(err, errlen, "platform %s is not a list", g_nodes[p].key);
        bool is_mine = strcmp(g_nodes[p].key, PLATFORM) == 0;
        mine = mine || is_mine;
        for (int f = g_nodes[p].child; f >= 0; f = g_nodes[f].next) {
            const char *fam = jis(f, J_STR) ? g_nodes[f].str : NULL;
            if (!fam || !fd_family_valid(fam)) return fail(err, errlen, "platform %s has a malformed family", g_nodes[p].key);
            if (!is_mine) continue;
            if (out->count == FD_FAMILIES_MAX) return fail(err, errlen, "too many families");
            snprintf(out->families[out->count++], FD_FAMILY_MAX, "%s", fam);
        }
    }
    if (!mine) return fail(err, errlen, "no " PLATFORM " families");
    // Optional ip_redirects, strict like the families: one bad entry rejects the file.
    int ipr = jget(root, "ip_redirects");
    if (ipr >= 0) {
        if (!jis(ipr, J_OBJ)) return fail(err, errlen, "ip_redirects is not an object");
        for (int p = g_nodes[ipr].child; p >= 0; p = g_nodes[p].next) {
            if (!jis(p, J_ARR)) return fail(err, errlen, "ip_redirects %s is not a list", g_nodes[p].key);
            bool is_mine = strcmp(g_nodes[p].key, PLATFORM) == 0;
            int first = out->ip_count;
            for (int e = g_nodes[p].child; e >= 0; e = g_nodes[e].next) {
                const char *from = jis(e, J_OBJ) ? jstr(e, "from") : NULL;
                const char *to = jis(e, J_OBJ) ? jstr(e, "to") : NULL;
                const char *proto = jis(e, J_OBJ) ? jstr(e, "proto") : NULL;
                int tn = jis(e, J_OBJ) ? jget(e, "title") : -1;
                const char *title = tn >= 0 ? (jis(tn, J_STR) ? g_nodes[tn].str : NULL) : "";
                if (!from || !to || !proto || !title || (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) ||
                    !fd_ip_endpoint_valid(from) || !fd_ip_endpoint_valid(to) || (title[0] && !title_valid(title)))
                    return fail(err, errlen, "ip_redirects %s has a malformed entry", g_nodes[p].key);
                if (!is_mine) continue;
                bool tcp = strcmp(proto, "tcp") == 0;
                for (int i = first; i < out->ip_count; i++)
                    if (out->ip[i].tcp == tcp && strcmp(out->ip[i].from, from) == 0)
                        return fail(err, errlen, "ip_redirects %s lists %s %s twice", g_nodes[p].key, proto, from);
                if (out->ip_count == FD_IP_MAX) return fail(err, errlen, "too many ip redirects");
                fd_ip_redirect *r = &out->ip[out->ip_count++];
                r->tcp = tcp;
                snprintf(r->title, sizeof(r->title), "%s", title);
                snprintf(r->from, sizeof(r->from), "%s", from);
                snprintf(r->to, sizeof(r->to), "%s", to);
            }
        }
    }
    return true;
}

bool fd_ceiling_verify(char *env, size_t len, fd_ceiling *out, char *err, int errlen) {
    memset(out, 0, sizeof(*out));
    if (len == 0 || len > FD_ENVELOPE_MAX) return fail(err, errlen, "envelope is %zu bytes", len);
    int root = json_parse(env, len);
    if (!jis(root, J_OBJ)) return fail(err, errlen, "envelope is not JSON");
    const char *p64 = jstr(root, "payload");
    long plen = p64 ? b64decode(p64, g_payload, sizeof(g_payload) - 1) : -1;
    if (plen <= 0) return fail(err, errlen, "payload is not base64");
    int sigs = jget(root, "signatures");
    if (!jis(sigs, J_ARR)) return fail(err, errlen, "no signatures");
    // Over the decoded bytes, never a re-serialisation; only then are they parsed.
    if (!signed_by_pinned_key(sigs, g_payload, (size_t)plen))
        return fail(err, errlen, "no valid signature under a pinned key");
    g_payload[plen] = '\0';
    int proot = json_parse((char *)g_payload, (size_t)plen);
    if (!jis(proot, J_OBJ)) return fail(err, errlen, "payload is not JSON");
    if (!payload_into(proot, out, err, errlen)) { memset(out, 0, sizeof(*out)); return false; }
    return true;
}

bool fd_ceiling_check(char *env, size_t len, long long high, fd_ceiling *out, char *err, int errlen) {
    char why[128];
    if (!fd_ceiling_verify(env, len, out, why, sizeof(why))) return fail(err, errlen, "ceiling rejected: %s", why);
    if (out->version < high) {
        long long got = out->version;
        memset(out, 0, sizeof(*out));
        return fail(err, errlen, "ceiling version %lld is older than %lld already accepted", got, high);
    }
    return true;
}

// ---- host lines: effective_rules + block text (hosts.c) -----------------------------

// dns_mitm's own matcher (wildcardcmp), copied from hosts.c openpak_glob.
bool fd_glob(const char *pattern, const char *string) {
    const char *w = NULL, *s = NULL;
    for (;;) {
        if (!*string) {
            if (!*pattern || *pattern == '*') return true;
            if (!s || !*s) return false;
            string = s++; pattern = w; continue;
        }
        if (*pattern != *string) {
            if (*pattern == '*') { w = ++pattern; s = string; if (*pattern) continue; return true; }
            if (w) { string++; continue; }
            return false;
        }
        pattern++; string++;
    }
}

static const char *const NAT_CHECK_NAMES[] = {
    "nncs1-%.n.n.srv.nintendo.net", "nncs2-%.n.n.srv.nintendo.net",
    "nncs1-lp1.n.n.srv.nintendo.net", "nncs2-lp1.n.n.srv.nintendo.net",
};
static bool catches_nat_check(const char *pattern) {
    for (size_t i = 0; i < sizeof(NAT_CHECK_NAMES) / sizeof(*NAT_CHECK_NAMES); i++)
        if (fd_glob(pattern, NAT_CHECK_NAMES[i])) return true;
    return false;
}
static const char *const NINTENDO_NET_SPLIT[] = {
    "*.s.n.srv", "*.p.srv", "*.ndas.srv", "*.frs.srv", "*.znc.srv", "*.acbaa.srv", "*.ctest.srv",
    "*.penne.srv", "*.vermillion.srv", "*.savanna.srv", "*.dg.srv", "*.er.srv", "*.scsi.srv",
    "*.npln.srv", "*.pctl.srv", "*.npns.srv", "*.five", "*.d4c", "*.cdn", "*.eshop", "*.op2",
    "*.dragons", "*.nso", "*.sun",
};
#define SPLIT_COUNT (sizeof(NINTENDO_NET_SPLIT) / sizeof(*NINTENDO_NET_SPLIT))

// The hostnames the profile manages, exactly the policy rules the NRO's line_targets_ours walks
// (before the nintendo.net split and the NAT-check exclusion), one per line. Filled by
// fd_build_block; conflict neutralisation matches foreign lines against it.
#define FD_PAT_MAX 0x6000
static char g_pat[FD_PAT_MAX];
static size_t g_patn;
static bool g_pat_over;
const char *fd_policy_patterns(void) { return g_pat; }
static void pat_add(const char *host) {
    size_t l = strlen(host);
    if (g_patn + l + 2 > sizeof(g_pat)) { g_pat_over = true; return; }
    memcpy(g_pat + g_patn, host, l);
    g_patn += l;
    g_pat[g_patn++] = '\n';
    g_pat[g_patn] = '\0';
}

typedef struct { char *p; size_t cap, n; bool over; int lines; } outbuf;
static void put(outbuf *o, const char *fmt, ...) {
    if (o->over) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(o->p + o->n, o->cap - o->n, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= o->cap - o->n) o->over = true; else o->n += (size_t)w;
}

// One rule as hosts.c effective_rules would write it: the nintendo.net family becomes its
// services, anything dns_mitm would answer for the NAT-check names is skipped, the rest is a
// plain "<address> <host>" line.
static void emit_rule(outbuf *o, const char *ip, const char *host, const char *addr) {
    pat_add(host);
    if (strcmp(host, "*.nintendo.net") == 0) {
        for (size_t k = 0; k < SPLIT_COUNT; k++) {
            put(o, "%s %s.nintendo.net\n", addr[0] ? addr : ip, NINTENDO_NET_SPLIT[k]);
            o->lines++;
        }
        return;
    }
    if (catches_nat_check(host)) return;
    put(o, "%s %s\n", addr[0] ? addr : ip, host);
    o->lines++;
}

static void note_drop(char *dropped, size_t cap, const char *name) {
    size_t n = strlen(dropped);
    if (n + 1 >= cap) return;
    snprintf(dropped + n, cap - n, "%s%s", n ? ", " : "", name);
}

bool fd_build_block(char *profile, size_t len, const fd_ceiling *c, const char *server_override,
                    char *block, size_t cap, size_t *blocklen, fd_stats *st, char *err, int errlen) {
    memset(st, 0, sizeof(*st));
    if (blocklen) *blocklen = 0;
    if (len == 0 || len > 256 * 1024) return fail(err, errlen, "profile is %zu bytes", len);
    int root = json_parse(profile, len);
    if (!jis(root, J_OBJ)) return fail(err, errlen, "profile is not JSON");
    int v = jget(root, "version");
    if (v >= 0 && (!jis(v, J_NUM) || g_nodes[v].num != 1)) return fail(err, errlen, "profile version is not 1");
    const char *platform = jstr(root, "platform");
    if (!platform || strcmp(platform, PLATFORM) != 0)
        return fail(err, errlen, "profile is for %s, not " PLATFORM, platform ? platform : "nothing");
    int redirect = jget(root, "redirect");
    if (!jis(redirect, J_OBJ)) return fail(err, errlen, "profile has no redirect section");

    // Server address: server.txt, else the profile's, else the built-in one (main_console.c load_ip).
    const char *ip = FD_DEFAULT_SERVER;
    int server = jget(root, "server");
    if (jis(server, J_OBJ)) {
        const char *a = jstr(server, "address");
        if (a && ipv4_valid(a)) ip = a;
    }
    if (server_override && server_override[0] && ipv4_valid(server_override)) ip = server_override;
    snprintf(st->server, sizeof(st->server), "%s", ip);
    g_patn = 0; g_pat[0] = '\0'; g_pat_over = false;

    // Pass 0 writes the family and exact rules, pass 1 the overrides: dns_mitm takes the last
    // matching line, so an override has to come after the wildcards.
    outbuf o = {block, cap, 0, false, 0};
    put(&o, "%s\n", FD_BEGIN);
    int suffixes = jget(redirect, "suffixes"), exact = jget(redirect, "exact");
    int overrides = jget(redirect, "overrides"), never = jget(redirect, "never");
    int rules = 0;
    char wild[HOST_MAX];

    if (jis(suffixes, J_ARR))
        for (int e = g_nodes[suffixes].child; e >= 0; e = g_nodes[e].next) {
            const char *f = jis(e, J_STR) ? g_nodes[e].str : "?";
            if (!fd_family_valid(f) || !fd_ceiling_covers(c, f)) { note_drop(st->dropped, sizeof(st->dropped), f); continue; }
            if (rules + 2 > FD_RULES_MAX) return fail(err, errlen, "profile carries more than %d rules", FD_RULES_MAX);
            snprintf(wild, sizeof(wild), "*%s", f);
            emit_rule(&o, ip, wild, "");        // "*.family"
            emit_rule(&o, ip, f + 1, "");       // its apex, which dns_mitm's wildcard does not answer
            rules += 2;
        }
    if (jis(exact, J_ARR))
        for (int e = g_nodes[exact].child; e >= 0; e = g_nodes[e].next) {
            const char *h = jis(e, J_STR) ? g_nodes[e].str : "?";
            if (!hostname_valid(h) || !fd_ceiling_covers(c, h)) { note_drop(st->dropped, sizeof(st->dropped), h); continue; }
            if (rules + 1 > FD_RULES_MAX) return fail(err, errlen, "profile carries more than %d rules", FD_RULES_MAX);
            emit_rule(&o, ip, h, "");
            rules++;
        }
    if (jis(overrides, J_OBJ))
        for (int e = g_nodes[overrides].child; e >= 0; e = g_nodes[e].next) {
            const char *name = g_nodes[e].key;
            const char *a = jis(e, J_STR) ? g_nodes[e].str : "";
            if (!hostname_valid(name) || !ipv4_valid(a) || !fd_ceiling_covers(c, name)) { note_drop(st->dropped, sizeof(st->dropped), name); continue; }
            if (rules + 1 > FD_RULES_MAX) return fail(err, errlen, "profile carries more than %d rules", FD_RULES_MAX);
            emit_rule(&o, ip, name, a);
            rules++;
        }
    // "never" cannot be written in a hosts file; reported like the NRO does.
    if (jis(never, J_ARR))
        for (int e = g_nodes[never].child; e >= 0; e = g_nodes[e].next)
            if (jis(e, J_STR)) {
                char label[HOST_MAX + 16];
                snprintf(label, sizeof(label), "never:%s", g_nodes[e].str);
                note_drop(st->dropped, sizeof(st->dropped), label);
            }
    put(&o, "%s\n", FD_END);
    if (o.over) return fail(err, errlen, "block does not fit in %zu bytes", cap);
    if (g_pat_over) return fail(err, errlen, "managed hostname list does not fit");
    if (rules == 0) return fail(err, errlen, "no profile name lies inside the signed ceiling");
    if (o.lines == 0) return fail(err, errlen, "profile leaves no host line to write");
    st->rules = rules;
    st->lines = o.lines;
    if (blocklen) *blocklen = o.n;
    return true;
}

// ---- replacing the marked block -----------------------------------------------------

static const char *find_mem(const char *h, size_t hl, const char *needle) {
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= hl; i++)
        if (memcmp(h + i, needle, nl) == 0) return h + i;
    return NULL;
}

// Locates the block: begin = first byte of the begin marker, after = first byte past the end
// marker's line (its newline included). Returns 0 none, 1 found, -1 malformed.
static int locate_block(const char *in, size_t inlen, const char **begin, const char **after) {
    const char *b = find_mem(in, inlen, FD_BEGIN);
    if (!b) return 0;
    size_t rest = inlen - (size_t)(b - in) - strlen(FD_BEGIN);
    const char *after_begin = b + strlen(FD_BEGIN);
    const char *e = find_mem(after_begin, rest, FD_END);
    if (!e) return -1;
    if (find_mem(after_begin, rest, FD_BEGIN) && find_mem(after_begin, rest, FD_BEGIN) < e) return -1;
    const char *t = e + strlen(FD_END);
    size_t tail = inlen - (size_t)(t - in);
    if (find_mem(t, tail, FD_BEGIN)) return -1;       // a second block: not ours to guess at
    if (tail && *t == '\r') { t++; tail--; }
    if (tail && *t == '\n') t++;
    *begin = b;
    *after = t;
    return 1;
}

// ---- conflicting foreign lines (hosts.c line_targets_ours / neutralize_conflicts) ----------

// True when a hosts line redirects one of the managed names. Same rules as the NRO: only the
// first hostname after the address is looked at, '#' lines and blank lines never match,
// "*.suffix" patterns match by case-sensitive suffix, plain names match exactly up to
// whitespace/end of line. The NRO reads at most 511 bytes of a line; so does this.
static bool line_targets_ours(const char *ln, size_t ll, const char *pats) {
    char line[512];
    size_t copy = ll < sizeof(line) - 1 ? ll : sizeof(line) - 1;
    memcpy(line, ln, copy);
    line[copy] = '\0';
    const char *l = line;
    while (*l == ' ' || *l == '\t') l++;
    if (*l == '#' || *l == '\0' || *l == '\r' || *l == '\n') return false;
    const char *host = l;
    while (*host && *host != ' ' && *host != '\t') host++;
    while (*host == ' ' || *host == '\t') host++;
    if (!*host) return false;
    for (const char *pat = pats; *pat;) {
        size_t pl = strcspn(pat, "\n");
        if (pat[0] == '*') {
            const char *suffix = pat + 1;
            size_t sl = pl - 1, hl = strcspn(host, " \t\r\n");
            if (hl >= sl && strncmp(host + hl - sl, suffix, sl) == 0) return true;
        } else if (pl && strncmp(host, pat, pl) == 0) {
            char after = host[pl];
            if (after == '\0' || after == ' ' || after == '\t' || after == '\r' || after == '\n') return true;
        }
        pat += pl + (pat[pl] ? 1 : 0);
    }
    return false;
}

// Copies [src, src+n) to out (NULL = only count) putting FD_DISABLED in front of every
// conflicting line. Returns the bytes produced; *hits counts the lines commented out.
static size_t neutralize(const char *src, size_t n, char *out, const char *pats, int *hits) {
    size_t o = 0, dl = strlen(FD_DISABLED);
    const char *p = src, *end = src + n;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t len = nl ? (size_t)(nl - p) + 1 : (size_t)(end - p);
        if (line_targets_ours(p, len, pats)) {
            if (out) memcpy(out + o, FD_DISABLED, dl);
            o += dl;
            (*hits)++;
        }
        if (out) memcpy(out + o, p, len);
        o += len;
        p += len;
    }
    return o;
}

// Fallback pattern list when the caller has none: every hostname the block itself writes.
static const char *patterns_from_block(const char *block, size_t blocklen) {
    g_patn = 0; g_pat[0] = '\0'; g_pat_over = false;
    const char *p = block, *end = block + blocklen, *line;
    while (p < end) {
        size_t n;
        line = p;
        while (p < end && *p != '\n') p++;
        n = (size_t)(p - line);
        if (p < end) p++;
        const char *q = line, *le = line + n;           // "<address> <host>"
        while (q < le && *q != ' ' && *q != '\t') q++;
        while (q < le && (*q == ' ' || *q == '\t')) q++;
        const char *h = q;
        while (q < le && *q != ' ' && *q != '\t' && *q != '\r') q++;
        if (n == 0 || line[0] == '#' || q == h || q - h > 191) continue;
        char host[192];
        memcpy(host, h, (size_t)(q - h)); host[q - h] = '\0';
        pat_add(host);
    }
    return g_pat;
}

fd_apply_result fd_apply_block_ex(const char *in, size_t inlen, const char *block, size_t blocklen, const char *pats,
                                  char *out, size_t cap, size_t *outlen, int *neutralized, char *err, int errlen) {
    *outlen = 0;
    int dummy = 0;
    if (!neutralized) neutralized = &dummy;
    *neutralized = 0;
    const char *b = NULL, *a = NULL;
    int loc = locate_block(in, inlen, &b, &a);
    if (loc == 0) return FD_APPLY_NO_BLOCK;
    if (loc < 0) { fail(err, errlen, "hosts file has a damaged or repeated openpak block"); return FD_APPLY_ERROR; }
    if (!pats) pats = patterns_from_block(block, blocklen);
    size_t head = (size_t)(b - in), tail = inlen - (size_t)(a - in);
    int h1 = 0, h2 = 0;
    size_t hn = neutralize(in, head, NULL, pats, &h1);
    size_t tn = neutralize(a, tail, NULL, pats, &h2);
    size_t total = hn + blocklen + tn;
    if (total >= FD_HOSTS_SAFE || total + 1 > cap) {
        fail(err, errlen, "hosts file would be %zu bytes; limit %d (Atmosphere aborts at %d)", total, FD_HOSTS_SAFE, FD_HOSTS_MAX);
        return FD_APPLY_ERROR;
    }
    h1 = h2 = 0;
    neutralize(in, head, out, pats, &h1);
    memcpy(out + hn, block, blocklen);
    neutralize(a, tail, out + hn + blocklen, pats, &h2);
    out[total] = '\0';
    *outlen = total;
    *neutralized = h1 + h2;
    return FD_APPLY_OK;
}

fd_apply_result fd_apply_block(const char *in, size_t inlen, const char *block, size_t blocklen,
                               char *out, size_t cap, size_t *outlen, char *err, int errlen) {
    return fd_apply_block_ex(in, inlen, block, blocklen, NULL, out, cap, outlen, NULL, err, errlen);
}

// Next line in [p, end): returns its length without the newline/CR, advances p.
static size_t next_line(const char **p, const char *end, const char **line) {
    *line = *p;
    const char *q = *p;
    while (q < end && *q != '\n') q++;
    size_t n = (size_t)(q - *p);
    *p = q < end ? q + 1 : q;
    while (n && (*line)[n - 1] == '\r') n--;
    return n;
}

static bool has_line(const char *text, size_t tl, const char *l, size_t ll) {
    const char *p = text, *end = text + tl, *line;
    while (p < end) {
        size_t n = next_line(&p, end, &line);
        if (n == ll && memcmp(line, l, n) == 0) return true;
    }
    return false;
}

void fd_block_diff(const char *in, size_t inlen, const char *block, size_t blocklen,
                   int *removed, int *added, int *kept, size_t *old_block_bytes) {
    *removed = *added = *kept = 0;
    *old_block_bytes = 0;
    const char *b = NULL, *a = NULL;
    const char *old = "";
    size_t ol = 0;
    if (locate_block(in, inlen, &b, &a) == 1) { old = b; ol = (size_t)(a - b); *old_block_bytes = ol; }
    const char *p = old, *end = old + ol, *line;
    while (p < end) {
        size_t n = next_line(&p, end, &line);
        if (has_line(block, blocklen, line, n)) (*kept)++; else (*removed)++;
    }
    p = block; end = block + blocklen;
    while (p < end) {
        size_t n = next_line(&p, end, &line);
        if (!has_line(old, ol, line, n)) (*added)++;
    }
}

// ---- HTTP ---------------------------------------------------------------------------

static bool header_value(const char *hdr, size_t hl, const char *name, char *val, size_t cap) {
    size_t nl = strlen(name);
    for (size_t i = 0; i + nl + 1 < hl; i++) {
        if ((i == 0 || hdr[i - 1] == '\n') && strncasecmp(hdr + i, name, nl) == 0 && hdr[i + nl] == ':') {
            size_t j = i + nl + 1, o = 0;
            while (j < hl && (hdr[j] == ' ' || hdr[j] == '\t')) j++;
            while (j < hl && hdr[j] != '\r' && hdr[j] != '\n' && o + 1 < cap) val[o++] = hdr[j++];
            val[o] = '\0';
            return true;
        }
    }
    return false;
}

bool fd_http_body(char *r, size_t total, int *status, char **body, size_t *blen, char *err, int errlen) {
    *status = 0; *body = NULL; *blen = 0;
    if (total < 12 || memcmp(r, "HTTP/1.", 7) != 0) return fail(err, errlen, "not an HTTP response");
    *status = (int)strtol(r + 9, NULL, 10);
    size_t hdr = 0;
    for (size_t i = 0; i + 3 < total; i++)
        if (r[i] == '\r' && r[i + 1] == '\n' && r[i + 2] == '\r' && r[i + 3] == '\n') { hdr = i + 4; break; }
    if (!hdr) return fail(err, errlen, "response headers are not complete");
    char val[64];
    char *b = r + hdr;
    size_t bl = total - hdr;
    if (header_value(r, hdr, "transfer-encoding", val, sizeof(val)) && strncasecmp(val, "chunked", 7) == 0) {
        char *rd = b, *wr = b, *end = b + bl;
        for (;;) {
            char *eol = rd;
            while (eol + 1 < end && !(eol[0] == '\r' && eol[1] == '\n')) eol++;
            if (eol + 1 >= end) return fail(err, errlen, "chunked body is truncated");
            char *e = NULL;
            unsigned long sz = strtoul(rd, &e, 16);
            if (e == rd || sz > bl) return fail(err, errlen, "bad chunk size");
            rd = eol + 2;
            if (sz == 0) break;
            if ((size_t)(end - rd) < sz + 2) return fail(err, errlen, "chunked body is truncated");
            memmove(wr, rd, sz);
            wr += sz;
            rd += sz + 2;
        }
        bl = (size_t)(wr - b);
    } else if (header_value(r, hdr, "content-length", val, sizeof(val))) {
        unsigned long cl = strtoul(val, NULL, 10);
        if (cl > bl) return fail(err, errlen, "body is truncated (%zu of %lu bytes)", bl, cl);
        bl = cl;
    }
    *body = b;
    *blen = bl;
    return true;
}

// ---- updating the hosts files -------------------------------------------------------

static char g_in[FD_HOSTS_MAX + 0x100];
static char g_out[FD_HOSTS_MAX + 0x100];

// 0 ok, -1 absent, -2 too big. NUL-terminates.
static int read_file(const char *path, char *buf, size_t cap, size_t *len) {
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap, f);
    int more = fgetc(f);
    fclose(f);
    if (more != EOF || n >= cap) return -2;
    buf[n] = '\0';
    *len = n;
    return 0;
}

static int write_plain(const char *path, const void *data, size_t len, void (*commit)(void)) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    int fl = fflush(f);
    fclose(f);
    if (commit) commit();
    return (w == len && fl == 0) ? 0 : -1;
}

// Temp file + read-back + rename, the previous content kept as <path>.openpak-prev. FAT cannot
// replace on rename, so the original is moved aside first and moved back if the second rename fails.
static int write_hosts(const char *path, const char *data, size_t len, fd_logfn lg, void (*commit)(void)) {
    char tmp[160], prev[160];
    snprintf(tmp, sizeof(tmp), "%s.openpak-tmp", path);
    snprintf(prev, sizeof(prev), "%s.openpak-prev", path);
    if (write_plain(tmp, data, len, commit) != 0) { lg("write: cannot write %s", tmp); remove(tmp); return -1; }
    size_t rl = 0;
    if (read_file(tmp, g_in, sizeof(g_in) - 1, &rl) != 0 || rl != len || memcmp(g_in, data, len) != 0) {
        lg("write: read-back of %s differs, abandoning", tmp);
        remove(tmp);
        return -1;
    }
    remove(prev);
    if (rename(path, prev) != 0) { lg("write: cannot keep %s as %s", path, prev); remove(tmp); return -1; }
    if (rename(tmp, path) != 0) {
        lg("write: rename of %s failed, restoring the previous file", tmp);
        rename(prev, path);
        remove(tmp);
        if (commit) commit();
        return -1;
    }
    if (commit) commit();
    return 0;
}

static const char *base_of(const char *p) { const char *s = strrchr(p, '/'); return s ? s + 1 : p; }

int fd_update_hosts(const char *const paths[], int npaths, const char *block, size_t blen, const char *pats,
                    bool real, bool *changed, fd_logfn lg, void (*commit)(void)) {
    enum { P_ABSENT, P_NO_BLOCK, P_UNCHANGED, P_CHANGE };
    int plan[8] = {0};
    char err[160];
    *changed = false;
    if (npaths > 8) return -1;

    // Plan both files first; any refusal leaves every file alone.
    for (int i = 0; i < npaths; i++) {
        size_t il = 0, ol = 0;
        int rr = read_file(paths[i], g_in, FD_HOSTS_MAX + 0xff, &il);
        if (rr == -1) { lg("hosts %s: file absent, nothing to update", base_of(paths[i])); continue; }
        if (rr == -2 || il >= FD_HOSTS_MAX) { lg("REFUSED: %s is already 0x8000 bytes or more; leaving every file alone", base_of(paths[i])); return -1; }
        int neut = 0;
        fd_apply_result r = fd_apply_block_ex(g_in, il, block, blen, pats, g_out, sizeof(g_out), &ol, &neut, err, sizeof(err));
        if (r == FD_APPLY_ERROR) { lg("REFUSED: %s: %s; leaving every file alone", base_of(paths[i]), err); return -1; }
        if (r == FD_APPLY_NO_BLOCK) {
            lg("hosts %s: no openpak block (the console never chose OpenPak here), skipped", base_of(paths[i]));
            plan[i] = P_NO_BLOCK;
            continue;
        }
        int rem, add, kept; size_t oldb;
        fd_block_diff(g_in, il, block, blen, &rem, &add, &kept, &oldb);
        bool same = ol == il && memcmp(g_in, g_out, il) == 0;
        lg("hosts %s: block old=%zu bytes, new=%zu bytes; lines removed=%d added=%d kept=%d; foreign lines to comment out=%d; file %zu -> %zu bytes (%s)",
           base_of(paths[i]), oldb, blen, rem, add, kept, neut, il, ol, same ? "unchanged" : "would change");
        plan[i] = same ? P_UNCHANGED : P_CHANGE;
    }
    if (!real) return 0;

    int written = 0;
    for (int i = 0; i < npaths; i++) {
        if (plan[i] != P_CHANGE) continue;
        size_t il = 0, ol = 0;
        if (read_file(paths[i], g_in, FD_HOSTS_MAX + 0xff, &il) != 0) { lg("write: %s vanished", base_of(paths[i])); return written; }
        int neut2 = 0;
        if (fd_apply_block_ex(g_in, il, block, blen, pats, g_out, sizeof(g_out), &ol, &neut2, err, sizeof(err)) != FD_APPLY_OK) { lg("write: replan failed: %s", err); return written; }
        lg("write: call write_hosts(%s, %zu bytes, %d foreign line(s) commented out)", base_of(paths[i]), ol, neut2);
        if (write_hosts(paths[i], g_out, ol, lg, commit) != 0) { lg("write: FAILED for %s, stopping", base_of(paths[i])); return written; }
        lg("write: %s updated (previous kept as .openpak-prev)", base_of(paths[i]));
        written++;
        *changed = true;
    }
    return written;
}
