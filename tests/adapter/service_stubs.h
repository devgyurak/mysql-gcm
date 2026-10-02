/* SPDX-License-Identifier: GPL-2.0-only */
/* Stub component services, so the component's lifecycle can be driven and made to fail.
 *
 * Why this works without a server and without a seam in the shipped code:
 * REQUIRES_SERVICE_PLACEHOLDER(x) expands to `SERVICE_TYPE(x) *mysql_service_x`
 * (component_implementation.h), so those placeholders are ordinary pointers that
 * src/component.cc defines. A test translation unit declares them extern and points them
 * at the structs below. Nothing is added to src/ — which matters, because
 * scripts/check-architecture.py fails the build if a test seam appears in a server adapter.
 *
 * Entry points: gcm_component_init and gcm_component_deinit live in an anonymous namespace,
 * so they are reached the way the loader reaches them — through the init/deinit members of
 * mysql_component_t, which DECLARE_COMPONENT puts in the extern `mysql_component_gcm`.
 *
 * Whether the fetched algorithms are still live is read through the core's own public API
 * rather than a new accessor: each operation returns Error::openssl when its handle is null
 * (src/gcm.cc, src/nonce.cc), and crypto_deinit() nulls all three. One probe per handle — see
 * probe_gcm / probe_mac / probe_cbc and the comment there for why one was not enough.
 */

#ifndef MYSQL_GCM_ADAPTER_SERVICE_STUBS_H
#define MYSQL_GCM_ADAPTER_SERVICE_STUBS_H

#include <cstddef>
#include <set>
#include <string>
#include <vector>

#include "envelope.h"

namespace gcm_adapter {

/* Every service call the component makes, in the order it made it. The name is the method;
   `detail` is the argument that identifies the call — a function name, or a sysvar name.
   `extra` carries the one other argument worth asserting on, currently the scope a 9.x
   variable read asked for, so that a read switched from SESSION to GLOBAL is visible. */
struct Call {
  std::string method;
  std::string detail;
  std::string extra;
};

/* One place to say "fail this call". `nth` is 1-based over calls to that method with that
   detail; 0 means every call. A `detail` of "" matches any. */
struct FailureRule {
  std::string method;
  std::string detail;
  int nth = 0;
  /* udf_unregister reports two things: a non-zero return and whether the function was
     still present. The component only treats (failed && was_present) as "still in use", so
     a stub has to be able to produce both shapes. */
  bool was_present = true;
};

/* Points the component's service placeholders at the stubs. Idempotent — the fixture calls it
   from every SetUp rather than once, so a case cannot depend on another having run. */
void install();

/* Clears recorded calls and failure rules. Call at the start of every case. */
void reset();

/* Clears the modelled registration state. Separate from reset() because a case often
   wants to drop its failure rules while keeping what is installed. */
void forget_registrations();

/* Makes the matching call return failure. */
void fail(const FailureRule &rule);

const std::vector<Call> &calls();

/* The recorded calls to one method, in order, as their details. */
std::vector<std::string> details_for(const std::string &method);

/* The `extra` of the first call to a method, or "" when it was never called. */
std::string extra_for(const std::string &method);

/* Every call as "method:detail", in order. Asserting on this is how an ordering decision gets
   pinned — a case that only checks *which* calls happened cannot see two of them swapped. */
std::vector<std::string> call_sequence();

/* What the stubs believe is registered right now, from the calls they saw. Modelling the
   state rather than only the call log is what lets a case assert that a function is *gone*
   instead of assuming it: `udf_unregister` returning failure with `was_present` false means
   the name was never there, and only a state model can tell that from a refusal. */
const std::set<std::string> &registered_udfs();
bool sysvar_is_registered();

/* One probe per fetched algorithm, each reaching it through the core's public API rather
   than a test-only accessor. They return the core's own Error, because collapsing to a bool
   would make `Error::rng` indistinguishable from a released handle.

   Three, not one: `seal` only ever checks the GCM handle (src/gcm.cc), so a probe built on
   encrypt_random alone cannot see the HMAC or CBC handles being leaked — which it could not,
   and a mutation removing mac_deinit() passed the suite before these were split out. */
gcm::Error probe_gcm();  // g_aes_gcm, via encrypt_random
gcm::Error probe_mac();  // g_hmac, via encrypt_det's nonce derivation
gcm::Error probe_cbc();  // g_aes_cbc, via decrypting a v1 envelope

/* True when all three are usable. */
bool algorithms_live();

/* True when all three report the released state. */
bool algorithms_released();

/* Drives the component the way the loader does, through mysql_component_t. */
int component_init();
int component_deinit();

}  // namespace gcm_adapter

#endif  // MYSQL_GCM_ADAPTER_SERVICE_STUBS_H
