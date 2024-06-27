#ifndef LECIES_GUID_H
#define LECIES_GUID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/**
 * Gets an empty GUID (<c>"00000000-0000-0000-0000-000000000000"</c>).
 * @return <c>"00000000-0000-0000-0000-000000000000"</c>
 */
LECIES_API lecies_guid lecies_empty_guid();

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only? Pass \c 0 for \c false, anything else for \c true.
 * @param hyphens Should the GUID contain hyphen separators? Pass \c 0 for \c false, anything else for \c true.
 * @return The lecies_guid
 */
LECIES_API lecies_guid lecies_new_guid(int lowercase, int hyphens);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LECIES_GUID_H
