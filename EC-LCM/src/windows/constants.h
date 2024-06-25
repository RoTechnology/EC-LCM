#ifndef LECIES_CONSTANTS_H
#define LECIES_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The version number of this LECIES implementation.
 * TODO: increase this and below string version accordingly BEFORE releasing new updates!
 */
#define LECIES_VERSION 403

/**
 * The version number of this LECIES implementation (nicely-formatted string).
 */
#define LECIES_VERSION_STR "4.0.3"

/**
 * Key size (in bytes) of an X25519 key (both public and private key have the same length).
 */
#define LECIES_X25519_KEY_SIZE 32

/**
 * Key size (in bytes) of an X448 key (both public and private key have the same length).
 */
#define LECIES_X448_KEY_SIZE 56

/*
 * Some error codes:
 */

#define LECIES_ENCRYPT_ERROR_CODE_NULL_ARG 1000
#define LECIES_ENCRYPT_ERROR_CODE_INVALID_ARG 1001
#define LECIES_ENCRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 1002
#define LECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY 1003
#define LECIES_ENCRYPT_ERROR_CODE_COMPRESSION_FAILED 1004

#define LECIES_DECRYPT_ERROR_CODE_NULL_ARG 2000
#define LECIES_DECRYPT_ERROR_CODE_INVALID_ARG 2001
#define LECIES_DECRYPT_ERROR_CODE_INSUFFICIENT_OUTPUT_BUFFER_SIZE 2002
#define LECIES_DECRYPT_ERROR_CODE_OUT_OF_MEMORY 2003

#define LECIES_KEYGEN_ERROR_CODE_NULL_ARG 7000
#define LECIES_KEYGEN_ERROR_CODE_INVALID_ARG 7001

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LECIES_CONSTANTS_H
