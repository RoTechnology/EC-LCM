#ifndef LECIES_KEYGEN_H
#define LECIES_KEYGEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"
#include "types.h"

/**
 * Generates a LECIES Curve25519 keypair and writes it into the specified output buffers.
 * @param output The lecies_curve25519_keypair instance into which to write the generated key-pair.
 * @param additional_entropy [OPTIONAL] Additional entropy bytes for the CSPRNG. Can be set to <c>NULL</c> if you wish not to add custom entropy.
 * @param additional_entropy_length [OPTIONAL] Length of the \p additional_entropy array. If \p additional_entropy is <c>NULL</c>, this value is ignored.
 * @return <c>0</c> if key generation succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
LECIES_API int lecies_generate_curve25519_keypair(lecies_curve25519_keypair* output, const uint8_t* additional_entropy, size_t additional_entropy_length);

/**
 * Generates a LECIES Curve448 keypair and writes it into the specified output buffers.
 * @param output The lecies_curve448_keypair instance into which to write the generated key-pair.
 * @param additional_entropy [OPTIONAL] Additional entropy bytes for the CSPRNG. Can be set to <c>NULL</c> if you wish not to add custom entropy.
 * @param additional_entropy_length [OPTIONAL] Length of the \p additional_entropy array. If \p additional_entropy is <c>NULL</c>, this value is ignored.
 * @return <c>0</c> if key generation succeeded; error codes as defined inside the header file or MbedTLS otherwise.
 */
LECIES_API int lecies_generate_curve448_keypair(lecies_curve448_keypair* output, const uint8_t* additional_entropy, size_t additional_entropy_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LECIES_KEYGEN_H
