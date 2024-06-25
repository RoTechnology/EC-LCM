#ifndef LECIES_TYPES_H
#define LECIES_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LECIES_DLL)
#ifdef LECIES_BUILD_DLL
#define LECIES_API __declspec(dllexport)
#else
#define LECIES_API __declspec(dllimport)
#endif
#else
#define LECIES_API
#endif

/**
 * Contains a Curve25519 key, encoded as a NUL-terminated hex-string.
 */
typedef struct lecies_curve25519_key
{
    /**
     * Hex-encoded string of a 32-byte Curve25519 key. <p>
     * For public keys, the 0x04 byte prefix is omitted. <p>
     * The 65th character is the NUL-terminator.
     */
    char hexstring[64 + 1];
} lecies_curve25519_key;

/**
 * Contains a stack-allocated lecies_curve25519_key keypair.
 */
typedef struct lecies_curve25519_keypair
{
    /**
     * The public key (formatted as a hex string). <p>
     * 64 bytes of hex string + 1 NUL-terminator.
     */
    lecies_curve25519_key public_key;

    /**
     * The private key (formatted as a hex string). <p>
     * 64 bytes of hex string + 1 NUL-terminator.
     */
    lecies_curve25519_key private_key;
} lecies_curve25519_keypair;

/**
 * Contains a Curve448 key, encoded as a NUL-terminated hex-string.
 */
typedef struct lecies_curve448_key
{
    /**
     * Hex-encoded string of a 56-byte Curve448 key. <p>
     * For public keys, the 0x04 byte prefix is omitted. <p>
     * The 113th character is the NUL-terminator.
     */
    char hexstring[112 + 1];
} lecies_curve448_key;

/**
 * Contains a stack-allocated Curve448 keypair.
 */
typedef struct lecies_curve448_keypair
{
    /**
     * The public key (formatted as a hex string). <p>
     * 112 bytes of hex string + 1 NUL-terminator. <p>
     * The <c>0x04</c> prefix byte that's required by the
     * EC key encoding standard is omitted in this implementation!
     */
    lecies_curve448_key public_key;

    /**
     * The private key (formatted as a hex string). <p>
     * 112 bytes of hex string + 1 NUL-terminator.
     */
    lecies_curve448_key private_key;
} lecies_curve448_keypair;

/**
 * @brief Struct containing the output from a call to the lecies_new_guid() function. <p>
 * 36 characters (only 32 if you chose to omit the hyphens) + 1 NUL terminator.
 */
typedef struct lecies_guid
{
    /** NUL-terminated string containing the GUID. */
    char string[36 + 1];
} lecies_guid;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LECIES_TYPES_H
