// SPDX-License-Identifier: AGPL-3.0-only
// openpak-fetchd core: everything that does not need libnx, so `make test` runs it on a PC.
//
// Ported from console/openpak-nro (the console tool whose output this daemon must reproduce
// byte for byte): ceiling.c (envelope verify, family rules, profile filtering, version rule),
// hosts.c (effective_rules: the nintendo.net split, the NAT-check exclusion, overrides last;
// block text; strip/replace of the marked block; the 0x8000 cap), policy.c (rule limits).
// Reimplemented: a small in-place JSON reader (the NRO links json-c), base64, HTTP body
// framing, block replacement that keeps every foreign line, the dry-run diff.
// NOT ported: the compiled fallback list, the signed v2 bundle path (policy.json), conflict
// neutralisation ("#openpak-off#" commenting of other tools' lines), the effective-set
// digest, CA/patch/news installation. See README-style notes in the test and TEST-PROCEDURE.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FD_BEGIN "# >>> openpak >>>"
#define FD_END   "# <<< openpak <<<"
#define FD_DISABLED "#openpak-off# "   // hosts.h OPENPAK_DISABLED
#define FD_HOSTS_MAX  0x8000   // ams_mitm aborts at boot on a hosts file of this size or more
#define FD_HOSTS_SAFE 0x7800   // we refuse to produce anything from here up (2 KiB margin)
#define FD_RULES_MAX  512      // policy.h OPENPAK_RULES_MAX: a profile with more is refused
#define FD_FAMILIES_MAX 64
#define FD_FAMILY_MAX   128
#define FD_ENVELOPE_MAX (32 * 1024)
#define FD_DEFAULT_SERVER "145.241.199.19"   // main_console.c OPENPAK_SERVER, last-resort address

typedef struct {
    const char *keyid;     // hex sha256 of the raw key
    uint8_t     pub[32];
} fd_pinned_key;

// The keys a ceiling is accepted under (docs/signed-ceiling.md). Tests repoint these.
extern const fd_pinned_key *fd_keys;
extern int fd_key_count;

typedef struct {
    long long version;
    int       count;
    char      families[FD_FAMILIES_MAX][FD_FAMILY_MAX];   // switch families only
} fd_ceiling;

typedef struct {
    int  rules;          // rules in the profile (NRO's policy count), before the nintendo.net split
    int  lines;          // host lines in the block
    char server[48];     // address the block points at
    char dropped[256];   // names left out (outside the ceiling / never), comma separated
} fd_stats;

bool fd_family_valid(const char *family);
bool fd_ceiling_covers(const fd_ceiling *c, const char *name);

// Verifies an envelope (modified in place: strings are unescaped) and fills out with the
// switch families. Signature first, over the decoded payload bytes; then the payload.
bool fd_ceiling_verify(char *env, size_t len, fd_ceiling *out, char *err, int errlen);
// verify + the rollback rule: refuses version < high (the highest ever accepted).
bool fd_ceiling_check(char *env, size_t len, long long high, fd_ceiling *out, char *err, int errlen);

// Profile (platform=switch) filtered through the ceiling, rendered as the host lines of the
// block, wrapped in the markers. server_override (server.txt) wins over the profile's own
// address, which wins over FD_DEFAULT_SERVER. block is NUL-terminated. Modifies profile.
bool fd_build_block(char *profile, size_t len, const fd_ceiling *c, const char *server_override,
                    char *block, size_t cap, size_t *blocklen, fd_stats *st, char *err, int errlen);

typedef enum { FD_APPLY_OK = 0, FD_APPLY_NO_BLOCK, FD_APPLY_ERROR } fd_apply_result;
// Replaces only the marked block of in with block; every other byte is copied as is, except
// conflicting foreign lines, which get FD_DISABLED (see fd_apply_block_ex; patterns = the block's hostnames). A file
// without a begin marker is left alone (FD_APPLY_NO_BLOCK: that console never chose OpenPak).
// Refuses a missing end marker, a second begin marker and a result of FD_HOSTS_SAFE or more.
fd_apply_result fd_apply_block(const char *in, size_t inlen, const char *block, size_t blocklen,
                               char *out, size_t cap, size_t *outlen, char *err, int errlen);

// Same, with the managed hostnames (newline separated, as fd_policy_patterns gives them; NULL =
// the hostnames of the block) and conflict neutralisation: every line outside the block that
// redirects one of them is prefixed with FD_DISABLED. *neutralized counts those lines (may be NULL).
fd_apply_result fd_apply_block_ex(const char *in, size_t inlen, const char *block, size_t blocklen, const char *pats,
                                  char *out, size_t cap, size_t *outlen, int *neutralized, char *err, int errlen);
// The policy hostnames of the last successful fd_build_block (the NRO's rules, before the split).
const char *fd_policy_patterns(void);

// Lines of the existing marked block that are not in the new one (removed) and vice versa.
void fd_block_diff(const char *in, size_t inlen, const char *block, size_t blocklen,
                   int *removed, int *added, int *kept, size_t *old_block_bytes);

// HTTP/1.x response framing: status, and the body located in place (Content-Length checked,
// chunked decoded). False if the response is truncated or not HTTP.
bool fd_http_body(char *resp, size_t total, int *status, char **body, size_t *blen, char *err, int errlen);

// The nintendo.net split exposed for tests.
bool fd_glob(const char *pattern, const char *string);

// Updates the marked block in each of paths (default.txt, emummc.txt). Plans every file first;
// one refusal (damaged markers, size limit, unreadable) leaves all of them alone and returns -1.
// real=false only plans and logs (a diff summary per file). Returns the files written.
// Files without a block (or absent) are skipped. Each write: temp file, read-back, previous
// kept as <path>.openpak-prev, rename; commit (may be NULL) is called after each step.
typedef void (*fd_logfn)(const char *fmt, ...);
// pats: managed hostnames (fd_policy_patterns()), or NULL to derive them from the block.
int fd_update_hosts(const char *const paths[], int npaths, const char *block, size_t blen, const char *pats,
                    bool real, bool *changed, fd_logfn lg, void (*commit)(void));
