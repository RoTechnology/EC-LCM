#ifndef LECIES_ENCRYPT_H
#define LECIES_ENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/**
 * Encrypts the given data using LECIES over Curve25519 and AES256-GCM.
 * @param data The data to encrypt.
 * @param data_length The length of the data array.
 * @param compress Should the \p data be compressed before being encrypted? Pass any integer value between [0; 9] (where \c 0 is no compression at all and \c 9 is the highest but slowest compression).
 * @param public_key The public key to encrypt the data with (hex-string format, as is the output of lecies_generate_curve25519_keypair()).
 * @param output Where to write the encrypted output into (this will ONLY be allocated if encryption succeeds; if the procedure fails in any way this is left untouched). On success: DO NOT FORGET TO FREE THIS YOURSELF! Use #lecies_free() for freeing.
 * @param output_length Where to write the output buffer length into.
 * @param output_base64 Should the encrypted output bytes be base64-encoded for easy transmission over e.g. email? If you decide to base64-encode the encrypted data buffer, please be aware that a NUL-terminator is appended at the end to allow usage as a
 * C-string but it will not be counted in \p output_length. Pass \c 0 for \c false, anything else for \c true.
 * @return <c>0</c> if encryption succeeded;  error codes as defined inside the header file or MbedTLS otherwise.
 */
LECIES_API int lecies_curve25519_encrypt(const uint8_t* data, size_t data_length, int compress, lecies_curve25519_key public_key, uint8_t** output, size_t* output_length, int output_base64);

/**
 * Encrypts the given data using LECIES over Curve448 and AES256-GCM.
 * @param data The data to encrypt.
 * @param data_length The length of the data array.
 * @param compress Should the \p data be compressed before being encrypted? Pass any integer value between [0; 9] (where \c 0 is no compression at all and \c 9 is highest but slowest compression).
 * @param public_key The public key to encrypt the data with (hex-string format, as is the output of lecies_generate_curve448_keypair()).
 * @param output Where to write the encrypted output into (this will ONLY be allocated if encryption succeeds; if the procedure fails in any way this is left untouched). On success: DO NOT FORGET TO FREE THIS YOURSELF! Use #lecies_free() for freeing.
 * @param output_length Where to write the output buffer length into.
 * @param output_base64 Should the encrypted output bytes be base64-encoded for easy transmission over e.g. email? If you decide to base64-encode the encrypted data buffer, please be aware that a NUL-terminator is appended at the end to allow usage as a
 * C-string but it will not be counted in \p output_length. Pass \c 0 for \c false, anything else for \c true.
 * @return <c>0</c> if encryption succeeded;  error codes as defined inside the header file or MbedTLS otherwise.
 */
LECIES_API int lecies_curve448_encrypt(const uint8_t* data, size_t data_length, int compress, lecies_curve448_key public_key, uint8_t** output, size_t* output_length, int output_base64);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LECIES_ENCRYPT_H
