// Fixtures copied from console/openpak-nro/source/ceiling_test.c: envelopes signed with the
// NRO test suite's throwaway key (seed 00 01 .. 1f), never the real ceiling key.
#pragma once
#include <stdint.h>
static const uint8_t test_pub[32] = {0x03,0xa1,0x07,0xbf,0xf3,0xce,0x10,0xbe,0x1d,0x70,0xdd,0x18,0xe7,0x4b,0xc0,0x99,0x67,0xe4,0xd6,0x30,0x9b,0xa5,0x0d,0x5f,0x1d,0xdc,0x86,0x64,0x12,0x55,0x31,0xb8};
static const char test_keyid[] = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c";
static const char ENV_V3[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjozLCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiLCIubmludGVuZG8uY29tIiwiLmRlbW9ud2FyZS5uZXQiXSwid2lpdSI6WyIubmludGVuZG8ubmV0IiwiLm5pbnRlbmRvd2lmaS5uZXQiXX19\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\",\n"
    "      \"sig\": \"k1yCg4mMY40UFaQU0owhUSNolnZL5A8PqFBcoDKZrqaZGH925bvvAFfPbUkpNJ7s1K5aY/+OixxbI4SBVIqrAQ==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;
static const char ENV_V2[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjoyLCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiXX19\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\",\n"
    "      \"sig\": \"h2FQC0xWi5kmHpUMCCOZoJHAzn3GxFjGrHQU8Le8GqviwTfFUPA5tuzs9E2Zv7HN/xcmUPAPYyqh4Yt1gUSnAA==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;
static const char ENV_V4_BAD_FAMILY[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjo0LCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiXSwid2lpdSI6WyIuY29tIl19fQ==\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\",\n"
    "      \"sig\": \"VwJk1lSjMtjuzTg5Jn0rsBOJZC5Egj4j+YL6TrCFEmGI0Ht+PSW23b64Qwm4J5NJIOZPxgmeDsldUKa5r0pYAQ==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;
static const char ENV_V5_WIIU_ONLY[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjo1LCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiLCIubmludGVuZG8uY29tIiwiLmRlbW9ud2FyZS5uZXQiXSwid2lpdSI6WyIubmludGVuZG8ubmV0IiwiLm9wZW5wYWsub3JnIl19LCJleHRyYSI6Imlnbm9yZWQifQ==\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\",\n"
    "      \"sig\": \"IdgyXnH/v4qgtEvdwCNaRkMJJvGbMV6UjwaGHVJ0VJCEoJRfi9p3TnwPArGj6Uz7T3eXy9N1Q6WnsCJp8wqLBQ==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;
static const char ENV_V3_TAMPERED[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjozLCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiLCIubmludGVuZG8uY29tIiwiLmV2aWx3YXJlLm5ldCJdLCJ3aWl1IjpbIi5uaW50ZW5kby5uZXQiLCIubmludGVuZG93aWZpLm5ldCJdfX0=\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\",\n"
    "      \"sig\": \"k1yCg4mMY40UFaQU0owhUSNolnZL5A8PqFBcoDKZrqaZGH925bvvAFfPbUkpNJ7s1K5aY/+OixxbI4SBVIqrAQ==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;
static const char ENV_V3_OTHER_KEY[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjozLCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiLCIubmludGVuZG8uY29tIiwiLmRlbW9ud2FyZS5uZXQiXSwid2lpdSI6WyIubmludGVuZG8ubmV0IiwiLm5pbnRlbmRvd2lmaS5uZXQiXX19\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\",\n"
    "      \"sig\": \"0hOfJWNIsulbJ5YDQJRh9wimt+TioAyj1InZUJ1MuS/o4tglu/gDPiYLBVaXFODGdanhEt73YTyKWtVI183TDw==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;
static const char ENV_V3_WRONG_KEYID[] =
    "{\n"
    "  \"payload\": \"eyJ0eXBlIjoib3BlbnBhay1jZWlsaW5nIiwiaXNzdWVkIjoiMjAyNi0wOS0yNFQxMDozMDowMFoiLCJ2ZXJzaW9uIjozLCJwbGF0Zm9ybXMiOnsic3dpdGNoIjpbIi5uaW50ZW5kby5uZXQiLCIubmludGVuZG8uY29tIiwiLmRlbW9ud2FyZS5uZXQiXSwid2lpdSI6WyIubmludGVuZG8ubmV0IiwiLm5pbnRlbmRvd2lmaS5uZXQiXX19\",\n"
    "  \"signatures\": [\n"
    "    {\n"
    "      \"keyid\": \"0000000000000000000000000000000000000000000000000000000000000000\",\n"
    "      \"sig\": \"k1yCg4mMY40UFaQU0owhUSNolnZL5A8PqFBcoDKZrqaZGH925bvvAFfPbUkpNJ7s1K5aY/+OixxbI4SBVIqrAQ==\"\n"
    "    }\n"
    "  ]\n"
    "}\n"
;

static const char PROFILE[] =
    "{\"version\":1,\"generated_at\":1790240666,\"platform\":\"switch\","
    "\"server\":{\"address\":\"198.51.100.7\",\"https_port\":443,\"http_port\":80},"
    "\"redirect\":{\"suffixes\":[\".nintendo.net\",\".newfamily.org\",\".ea.com\",\".com\"],"
    "\"exact\":[\"x.demonware.net\",\"evil.example.com\",\"bad name.nintendo.net\"],\"never\":[],"
    "\"overrides\":{\"nncs2-lp1.n.n.srv.nintendo.net\":\"203.0.113.9\",\"nat.example.com\":\"1.1.1.1\","
    "\"inject.nintendo.net\":\"1.2.3.4\\n5.6.7.8 x.com\"}},\"services\":[],\"recheck_after\":21600}";

