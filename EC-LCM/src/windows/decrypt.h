#ifndef LECIES_DECRYPT_H
#define LECIES_DECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/**
 * Decrypts the given data using LECIES, Curve25519 and AES256-GCM.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length The length of the data array.
 * @param encrypted_data_base64 Is the input \p encrypted_data base64-encoded? Pass \c 0 for \c false, anything else for \c true.
 * @param private_key The private key to decrypt the data with (hex-string, as is the output of lecies_generate_curve25519_keypair()). This is passed by value and will be destroyed after usage!
 * @param output Where to write the decrypted output into (this will ONLY be allocated if decryption succeeds; if the procedure fails in any way this is left untouched). On success: DO NOT FORGET TO FREE THIS YOURSELF! Use #lecies_free() for freeing.
 * @param output_length Where to write the output buffer length into (how many bytes were written into it).
 * @return <c>0</c> if decryption succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
LECIES_API int lecies_curve25519_decrypt(const uint8_t* encrypted_data, size_t encrypted_data_length, int encrypted_data_base64, lecies_curve25519_key private_key, uint8_t** output, size_t* output_length);

/**
 * Decrypts the given data using LECIES, Curve448 and AES256-GCM.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length The length of the data array.
 * @param encrypted_data_base64 Is the input \p encrypted_data base64-encoded? Pass \c 0 for \c false, anything else for \c true.
 * @param private_key The private key to decrypt the data with (hex-string, as is the output of lecies_generate_curve448_keypair()). This is passed by value and will be destroyed after usage!
 * @param output Where to write the decrypted output into (this will ONLY be allocated if decryption succeeds; if the procedure fails in any way this is left untouched). On success: DO NOT FORGET TO FREE THIS YOURSELF! Use #lecies_free() for freeing.
 * @param output_length Where to write the output buffer length into (how many bytes were written into it).
 * @return <c>0</c> if decryption succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
LECIES_API int lecies_curve448_decrypt(const uint8_t* encrypted_data, size_t encrypted_data_length, int encrypted_data_base64, lecies_curve448_key private_key, uint8_t** output, size_t* output_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LECIES_DECRYPT_H
