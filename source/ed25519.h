// Ed25519 signature verification (verify only) for the signed redirect ceiling.
// Vendored from TweetNaCl (public domain), see ed25519.c.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// True when sig (64 bytes) is a valid Ed25519 signature of msg under pub (32 bytes).
bool openpak_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t len,
                            const uint8_t pub[32]);
