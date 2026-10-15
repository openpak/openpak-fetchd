// Cross-check: the block openpak-fetchd builds must equal, byte for byte, what console/openpak-nro's
// own code (hosts.c openpak_enable on an empty hosts file) writes for the same ceiling and profile.
// Built only when the NRO sources and json-c/openssl are present (see Makefile).
//   nro_compare                          fixture ceiling (NRO test key) + fixture profile
//   nro_compare <ceiling> <profile>      live files under the real pinned key
#include "../source/core.h"
#include "fixtures.h"
#include "ceiling.h"
#include "hosts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char root[512];

static void put(const char *rel, const char *data, size_t len) {
    char path[600];
    snprintf(path, sizeof(path), "%s%s", root, rel);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(2); }
    fwrite(data, 1, len, f);
    fclose(f);
}
static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    char *b = malloc(1 << 20);
    *len = fread(b, 1, (1 << 20) - 1, f);
    b[*len] = 0;
    fclose(f);
    return b;
}

static const openpak_pinned_key nro_test = {NULL, {0}};
static openpak_pinned_key nro_key;
static fd_pinned_key fd_key;

int main(int argc, char **argv) {
    (void)nro_test;
    const char *tmp = getenv("TMPDIR");
    snprintf(root, sizeof(root), "%s/fd_nro_compare_XXXXXX", tmp ? tmp : ".");
    if (!mkdtemp(root)) { perror("mkdtemp"); return 2; }
    char p[600];
    snprintf(p, sizeof(p), "%s/atmosphere", root); mkdir(p, 0777);
    snprintf(p, sizeof(p), "%s/atmosphere/hosts", root); mkdir(p, 0777);
    snprintf(p, sizeof(p), "%s/switch", root); mkdir(p, 0777);
    snprintf(p, sizeof(p), "%s/switch/openpak", root); mkdir(p, 0777);
    openpak_root = root;

    char *env, *prof;
    size_t el, pl;
    if (argc >= 3) {
        env = slurp(argv[1], &el);
        prof = slurp(argv[2], &pl);
    } else {
        env = strdup(ENV_V3); el = strlen(env);
        prof = strdup(PROFILE); pl = strlen(prof);
        nro_key.keyid = test_keyid; memcpy(nro_key.pub, test_pub, 32);
        openpak_ceiling_keys = &nro_key; openpak_ceiling_key_count = 1;
        fd_key.keyid = test_keyid; memcpy(fd_key.pub, test_pub, 32);
        fd_keys = &fd_key; fd_key_count = 1;
    }
    // NRO side: the files the tool caches, then openpak_enable with the address load_ip() would pick.
    put(OPENPAK_CEILING_CACHE, env, el);
    put(OPENPAK_PROFILE_CACHE, prof, pl);
    openpak_policy_reload();
    char err[200];
    const openpak_policy *pol = openpak_active_policy();
    if (pol->source != OPENPAK_SOURCE_PROFILE_SAVED || !pol->address[0]) {
        printf("nro_compare: NRO did not load the profile (source %d problem '%s')\n", pol->source, openpak_policy_problem());
        return 1;
    }
    char ip[64];
    snprintf(ip, sizeof(ip), "%s", pol->address);
    if (!openpak_enable(ip, err, sizeof(err))) { printf("nro_compare: NRO openpak_enable failed: %s\n", err); return 1; }
    snprintf(p, sizeof(p), "%s/atmosphere/hosts/default.txt", root);
    size_t nl;
    char *nro = slurp(p, &nl);

    // fetchd side
    char *e2 = malloc(el + 1); memcpy(e2, env, el);
    char *pr2 = malloc(pl + 1); memcpy(pr2, prof, pl);
    fd_ceiling c;
    static char block[0x6000];
    size_t bl;
    fd_stats st;
    if (!fd_ceiling_check(e2, el, 0, &c, err, sizeof(err))) { printf("nro_compare: fetchd ceiling: %s\n", err); return 1; }
    if (!fd_build_block(pr2, pl, &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err))) { printf("nro_compare: fetchd block: %s\n", err); return 1; }

    int same = nl == bl && memcmp(nro, block, bl) == 0;
    printf("nro_compare: NRO block %zu bytes, fetchd block %zu bytes (%d host lines): %s\n", nl, bl, st.lines, same ? "IDENTICAL" : "DIFFERENT");
    if (!same) {
        FILE *f = fopen("nro.out", "wb"); fwrite(nro, 1, nl, f); fclose(f);
        f = fopen("fetchd.out", "wb"); fwrite(block, 1, bl, f); fclose(f);
    }
    // Second comparison: the full file, with foreign lines (conflicting, unrelated, comments, already
    // prefixed, wildcard, case, CRLF, no trailing newline in the last line) before an old block at
    // the end. The NRO's openpak_enable output must equal fetchd's fd_apply_block_ex output byte for byte.
    static const char *foreign =
        "# my hosts\n"
        "1.2.3.4 x.demonware.net\n"
        "1.2.3.4 demonware.net\n"
        "5.6.7.8 foo.bar.nintendo.net\r\n"
        "5.6.7.8 nintendo.net extra.example.org\n"
        "9.9.9.9\tY.DEMONWARE.NET\n"
        "  1.1.1.1   *.demonware.net # note\n"
        "1.1.1.1 demonware.net.evil.example\n"
        "1.1.1.1 notdemonware.net\n"
        "1.1.1.1 unrelated.example.org\n"
        "#1.1.1.1 x.demonware.net\n"
        "#openpak-off# 2.2.2.2 x.demonware.net\n"
        "\n"
        "7.7.7.7 nncs2-lp1.n.n.srv.nintendo.net\n"
        "3.3.3.3 last.demonware.net";
    char old[2048];
    snprintf(old, sizeof(old), "%s\n%s\n1.1.1.1 old.example.com\n%s\n", foreign, OPENPAK_BEGIN, OPENPAK_END);
    put("/atmosphere/hosts/default.txt", old, strlen(old));
    if (!openpak_enable(ip, err, sizeof(err))) { printf("nro_compare: NRO openpak_enable (2) failed: %s\n", err); return 1; }
    snprintf(p, sizeof(p), "%s/atmosphere/hosts/default.txt", root);
    char *nro2 = slurp(p, &nl);
    static char out[0x8000];
    size_t ol = 0;
    int neut = 0;
    fd_apply_result ar = fd_apply_block_ex(old, strlen(old), block, bl, fd_policy_patterns(), out, sizeof(out), &ol, &neut, err, sizeof(err));
    int same2 = ar == FD_APPLY_OK && ol == nl && memcmp(nro2, out, ol) == 0;
    printf("nro_compare: full hosts file, %d foreign lines commented out by fetchd: NRO %zu bytes, fetchd %zu bytes: %s\n",
           neut, nl, ol, same2 ? "IDENTICAL" : "DIFFERENT");
    if (!same2) {
        FILE *f = fopen("nro2.out", "wb"); fwrite(nro2, 1, nl, f); fclose(f);
        f = fopen("fetchd2.out", "wb"); fwrite(out, 1, ol, f); fclose(f);
    }
    same = same && same2;

    char cmd[640];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
    if (system(cmd) != 0) return 1;
    return same ? 0 : 1;
}
