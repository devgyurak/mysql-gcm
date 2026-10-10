/* SPDX-License-Identifier: GPL-2.0-only */
/* Registration and reading of the one sysvar, gcm.strict.

   Scope is not a free choice (docs/design.md amendment A5): component sysvars
   only honour PLUGIN_VAR_THDLOCAL from MySQL 9.0.0 on, and
   mysql_system_variable_reader — the only service that can read a *session*
   value — arrived in the same release. On 8.0/8.4 the server would treat the
   address of our global as a per-THD storage offset, so the variable is
   registered GLOBAL-only there. */

#ifndef MYSQL_GCM_SYSVAR_H
#define MYSQL_GCM_SYSVAR_H

#include <cstddef>

#include <mysql_version.h>

#ifndef MYSQL_VERSION_ID
#error "mysql_version.h did not define MYSQL_VERSION_ID (in-tree build expected)"
#endif

#define GCM_HAS_SESSION_SYSVAR (MYSQL_VERSION_ID >= 90000)

namespace gcm {

/* MySQL service convention: true means failure.

   Both variables are registered and unregistered as a unit: sysvar_register()
   rolls the first back if the second fails, and sysvar_unregister() attempts
   both and combines the failures. The component sees one step, which keeps the
   A9 ordering in component.cc about functions-then-variables rather than about
   how many variables there happen to be. */
/* On failure, rolls back anything it registered and reports through
   *fully_rolled_back whether that succeeded. False means a variable is still in
   the server's dictionary pointing at this component, so the caller must keep
   the crypto handles (design A9). */
bool sysvar_register(bool *fully_rolled_back);
bool sysvar_unregister();

/* The effective gcm.strict for the calling session — the GLOBAL value on
   8.0/8.4, where session scope does not exist. Any failure reads as ON, so a
   lost setting never downgrades a tag mismatch to NULL (fail closed).

   Call this once per statement from a UDF init, never per row: on 9.x it walks
   the system-variable hash under a read lock and converts the value to a
   string. SET SESSION only takes effect at statement boundaries anyway. */
bool strict_enabled();

/* The smallest key gcm_encrypt and gcm_encrypt_det accept, in bytes
   (gcm.min_key_bytes, design A10). GLOBAL on every version, so this is an
   administrator policy and not something a session can lower for itself.

   Read once per statement from a UDF init, like strict_enabled(), and never on
   the row path. Any failure answers kKeyLen256 — for a floor, failing closed
   means refusing the weaker suites. Decryption never consults it, so raising the
   floor cannot lock out data that was written under a lower one. */
size_t min_key_bytes();

}  // namespace gcm

#endif  // MYSQL_GCM_SYSVAR_H
