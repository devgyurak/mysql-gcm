/* SPDX-License-Identifier: GPL-2.0-only */
#include "service_stubs.h"

#include <cstdarg>
#include <cstring>
#include <map>

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/component_sys_var_service.h>
#include <mysql/components/services/mysql_runtime_error.h>
#include <mysql/components/services/udf_metadata.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/udf_registration_types.h>

#include "gcm.h"
#include "nonce.h"
#include "sysvar.h"

#if GCM_HAS_SESSION_SYSVAR
#include <mysql/components/services/mysql_current_thread_reader.h>
#include <mysql/components/services/mysql_system_variable.h>
#endif

/* Defined by src/component.cc; the loader would normally fill these in. */
extern SERVICE_TYPE(udf_registration) * mysql_service_udf_registration;
extern SERVICE_TYPE(mysql_udf_metadata) * mysql_service_mysql_udf_metadata;
extern SERVICE_TYPE(component_sys_variable_register) *
    mysql_service_component_sys_variable_register;
extern SERVICE_TYPE(component_sys_variable_unregister) *
    mysql_service_component_sys_variable_unregister;
extern SERVICE_TYPE(mysql_runtime_error) * mysql_service_mysql_runtime_error;
#if GCM_HAS_SESSION_SYSVAR
extern SERVICE_TYPE(mysql_system_variable_reader) * mysql_service_mysql_system_variable_reader;
extern SERVICE_TYPE(mysql_current_thread_reader) * mysql_service_mysql_current_thread_reader;
#endif

/* DECLARE_COMPONENT's struct, holding the init/deinit the loader calls. */
extern mysql_component_t COMPONENT_REF(gcm);

namespace gcm_adapter {
namespace {

std::vector<Call> g_calls;
std::vector<FailureRule> g_rules;
std::set<std::string> g_registered_udfs;
/* Per-name, not a single flag: the component now registers two variables as a
   unit (gcm.strict and gcm.min_key_bytes, design A10), and the branch where the
   second fails has to roll the first back. A single bool cannot see that. */
std::set<std::string> g_registered_vars;

/* Overrides for what a read returns, by "component.name". Without this a test
   cannot drive the parsing side of min_key_bytes() at all, and a regression that
   answered 16 on a malformed value would pass unnoticed. */
std::map<std::string, std::string> g_sysvar_values;

/* Returns the matching rule, or nullptr. Counts only calls already recorded for this
   method+detail, so `nth` is 1-based over the sequence the component produces. */
const FailureRule *rule_for(const std::string &method, const std::string &detail) {
  size_t seen = 0;
  for (const Call &call : g_calls) {
    if (call.method == method && call.detail == detail) ++seen;
  }
  for (const FailureRule &rule : g_rules) {
    if (rule.method != method) continue;
    if (!rule.detail.empty() && rule.detail != detail) continue;
    if (rule.nth == 0 || static_cast<size_t>(rule.nth) == seen + 1) return &rule;
  }
  return nullptr;
}

bool record_and_decide(const char *method, const char *detail, bool *was_present,
                       const char *extra = "") {
  const std::string m = method;
  const std::string d = detail == nullptr ? "" : detail;
  const FailureRule *rule = rule_for(m, d);
  g_calls.push_back(Call{m, d, extra == nullptr ? "" : extra});
  if (was_present != nullptr) *was_present = rule != nullptr ? rule->was_present : true;
  return rule != nullptr;
}

/* ---- udf_registration ---- */

DEFINE_BOOL_METHOD(stub_udf_register,
                   (const char *name, Item_result, Udf_func_any, Udf_func_init, Udf_func_deinit)) {
  if (record_and_decide("udf_register", name, nullptr)) return true;
  g_registered_udfs.insert(name);
  return false;
}

DEFINE_BOOL_METHOD(stub_udf_unregister, (const char *name, int *was_present)) {
  bool present = true;
  const bool failed = record_and_decide("udf_unregister", name, &present);
  /* The real service writes was_present before any failure return (sql/sql_udf.cc), and the
     component relies on that, so the stub does the same. */
  if (was_present != nullptr) *was_present = present ? 1 : 0;
  /* State follows the real service's meaning: failure with was_present false means the name
     was not there, so it is gone either way. Failure with was_present true means it is still
     registered and in use. */
  if (!failed || !present) g_registered_udfs.erase(name);
  return failed;
}

/* ---- mysql_udf_metadata: recorded, never failed. The charset contract is covered by the
   integration suite against a real server; here it only has to not crash. ---- */

DEFINE_BOOL_METHOD(stub_argument_get, (UDF_ARGS *, const char *, unsigned int, void **)) {
  return false;
}
DEFINE_BOOL_METHOD(stub_result_get, (UDF_INIT *, const char *, void **)) { return false; }
DEFINE_BOOL_METHOD(stub_argument_set, (UDF_ARGS *, const char *, unsigned int, void *)) {
  return false;
}
DEFINE_BOOL_METHOD(stub_result_set, (UDF_INIT *, const char *, void *)) { return false; }

/* ---- component_sys_variable_register / _unregister ---- */

DEFINE_BOOL_METHOD(stub_register_variable,
                   (const char *component_name, const char *name, int, const char *,
                    mysql_sys_var_check_func, mysql_sys_var_update_func, void *, void *)) {
  const std::string detail = std::string(component_name) + "." + name;
  if (record_and_decide("register_variable", detail.c_str(), nullptr)) return true;
  g_registered_vars.insert(detail);
  return false;
}

/* Writes the SHOW form of the bool into the caller's buffer, with the real service's contract:
   NUL terminated, length excluding the NUL, failure rather than truncation when it does not fit.
   Shared so that neither stub records a call on behalf of the other — a stub that delegated to
   another stub counted one read as two, which is a property of the harness and not of the
   component. */
bool write_sysvar_value(const std::string &name, void **val, size_t *out_length_of_val) {
  /* The SHOW form of each variable: a bool renders as ON/OFF and an int as its
     digits, which is what the component parses. A test may override either. */
  const auto override_it = g_sysvar_values.find(name);
  const std::string fallback = name == "gcm.min_key_bytes" ? "32" : "ON";
  const std::string &stored = override_it != g_sysvar_values.end() ? override_it->second : fallback;
  const char *value = stored.c_str();
  const size_t len = stored.size();
  if (val == nullptr || *val == nullptr || out_length_of_val == nullptr) return true;
  if (*out_length_of_val < len + 1) {
    *out_length_of_val = len + 1;
    return true;
  }
  std::memcpy(*val, value, len + 1);
  *out_length_of_val = len;
  return false;
}

DEFINE_BOOL_METHOD(stub_get_variable, (const char *component_name, const char *name, void **val,
                                       size_t *out_length_of_val)) {
  const std::string detail = std::string(component_name) + "." + name;
  if (record_and_decide("get_variable", detail.c_str(), nullptr)) return true;
  /* The real service fails for a variable that is not registered, which is what makes the
     window opened by registering the variable last fail closed (design A9). Modelling it here
     is what lets a case assert that. */
  if (g_registered_vars.count(detail) == 0) return true;
  /* strict always ON and the floor always 32: the other values are covered where
     they matter, against a real server (31_strict_scope, 32_min_key_bytes,
     strict_scope_global). */
  return write_sysvar_value(detail, val, out_length_of_val);
}

DEFINE_BOOL_METHOD(stub_unregister_variable, (const char *component_name, const char *name)) {
  const std::string detail = std::string(component_name) + "." + name;
  if (record_and_decide("unregister_variable", detail.c_str(), nullptr)) return true;
  /* The real service fails for a variable it does not have — measured on 8.4,
     where mysql_component_sys_variable_imp::unregister_variable looks the name up
     and returns true when it is absent. Returning success here hid a defect: the
     component attempted both unregisters unconditionally, so a refused UNINSTALL
     that had already removed one left every retry failing on the one that was
     gone. Modelling the real behaviour is what makes that testable. */
  if (g_registered_vars.erase(detail) == 0) return true;
  return false;
}

/* ---- mysql_runtime_error: the component only raises SQL errors from UDF bodies, which
   these tests do not drive. Recorded so an unexpected one is visible. ---- */

DEFINE_METHOD(void, stub_emit, (int, int, va_list)) {
  g_calls.push_back(Call{"error_emit", "", ""});
}

#if GCM_HAS_SESSION_SYSVAR
DEFINE_BOOL_METHOD(stub_system_variable_get,
                   (MYSQL_THD, const char *variable_type, const char *component_name,
                    const char *name, void **val, size_t *len)) {
  /* The scope is recorded, so a read switched from SESSION to GLOBAL — which would silently
     ignore SET SESSION on the one major where it works (design A5) — is assertable. */
  const std::string detail = std::string(component_name) + "." + name;
  if (record_and_decide("variable_reader_get", detail.c_str(), nullptr, variable_type)) {
    return true;
  }
  if (g_registered_vars.count(detail) == 0) return true;
  return write_sysvar_value(detail, val, len);
}

DEFINE_BOOL_METHOD(stub_current_thread_get, (MYSQL_THD * thd)) {
  /* A non-null opaque handle: strict_enabled() only checks it against nullptr. */
  static int fake_thd = 0;
  if (thd == nullptr) return true;
  *thd = reinterpret_cast<MYSQL_THD>(&fake_thd);
  return false;
}
#endif

SERVICE_TYPE(udf_registration) g_udf_registration{stub_udf_register, stub_udf_unregister};
SERVICE_TYPE(mysql_udf_metadata)
g_udf_metadata{stub_argument_get, stub_result_get, stub_argument_set, stub_result_set};
SERVICE_TYPE(component_sys_variable_register)
g_sysvar_register{stub_register_variable, stub_get_variable};
SERVICE_TYPE(component_sys_variable_unregister) g_sysvar_unregister{stub_unregister_variable};
SERVICE_TYPE(mysql_runtime_error) g_runtime_error{stub_emit};
#if GCM_HAS_SESSION_SYSVAR
SERVICE_TYPE(mysql_system_variable_reader) g_variable_reader{stub_system_variable_get};
SERVICE_TYPE(mysql_current_thread_reader) g_thread_reader{stub_current_thread_get};
#endif

const unsigned char kKey[gcm::kKeyLen256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

}  // namespace

void install() {
  mysql_service_udf_registration = &g_udf_registration;
  mysql_service_mysql_udf_metadata = &g_udf_metadata;
  mysql_service_component_sys_variable_register = &g_sysvar_register;
  mysql_service_component_sys_variable_unregister = &g_sysvar_unregister;
  mysql_service_mysql_runtime_error = &g_runtime_error;
#if GCM_HAS_SESSION_SYSVAR
  mysql_service_mysql_system_variable_reader = &g_variable_reader;
  mysql_service_mysql_current_thread_reader = &g_thread_reader;
#endif
}

void reset() {
  g_calls.clear();
  g_rules.clear();
  g_sysvar_values.clear();
}

void set_sysvar_value(const std::string &name, const std::string &value) {
  g_sysvar_values[name] = value;
}

void forget_registrations() {
  g_registered_udfs.clear();
  g_registered_vars.clear();
}

void fail(const FailureRule &rule) { g_rules.push_back(rule); }

const std::vector<Call> &calls() { return g_calls; }

std::vector<std::string> details_for(const std::string &method) {
  std::vector<std::string> out;
  for (const Call &call : g_calls) {
    if (call.method == method) out.push_back(call.detail);
  }
  return out;
}

std::string extra_for(const std::string &method) {
  for (const Call &call : g_calls) {
    if (call.method == method) return call.extra;
  }
  return "";
}

std::vector<std::string> call_sequence() {
  std::vector<std::string> out;
  for (const Call &call : g_calls) {
    out.push_back(call.method + ":" + call.detail);
  }
  return out;
}

const std::set<std::string> &registered_udfs() { return g_registered_udfs; }

bool sysvar_is_registered() { return g_registered_vars.count("gcm.strict") != 0; }

bool min_key_bytes_is_registered() { return g_registered_vars.count("gcm.min_key_bytes") != 0; }

gcm::Error probe_gcm() {
  const unsigned char plaintext[] = {'x'};
  unsigned char envelope[gcm::encrypt_out_len(sizeof(plaintext))] = {};
  size_t written = 0;
  return gcm::encrypt_random(gcm::Bytes{kKey, sizeof(kKey)},
                             gcm::Bytes{plaintext, sizeof(plaintext)}, gcm::Bytes{nullptr, 0},
                             envelope, &written);
}

gcm::Error probe_mac() {
  /* derive_det_nonce, not encrypt_det. The deterministic variant derives its nonce and *then*
     seals, so encrypt_det reports Error::openssl from the cipher handle whether or not the MAC
     handle is alive — which is exactly how a mutation removing mac_deinit() passed the suite.
     This is the narrowest public entry point that touches g_hmac and nothing else
     (spec/envelope.md §3). */
  const unsigned char plaintext[] = {'x'};
  unsigned char nonce[gcm::kNonceLen] = {};
  return gcm::derive_det_nonce(gcm::Bytes{kKey, sizeof(kKey)},
                               gcm::Bytes{plaintext, sizeof(plaintext)}, nonce);
}

gcm::Error probe_cbc() {
  /* v1 is the only envelope version that uses AES-256-CBC, and it is decrypt-only, so the CBC
     handle is reachable only this way. The bytes are not a real v1 envelope — version, a 16
     byte IV and one block of nonsense — which is enough: a released handle is refused before
     anything is decrypted, and a live one gets far enough to return something else. */
  unsigned char envelope[gcm::kMinCbcLen] = {};
  envelope[0] = gcm::kVersionLegacyCbc;
  unsigned char out[sizeof(envelope)] = {};
  size_t written = 0;
  return gcm::decrypt(gcm::Bytes{kKey, sizeof(kKey)}, gcm::Bytes{envelope, sizeof(envelope)},
                      gcm::Bytes{nullptr, 0}, out, &written);
}

bool algorithms_live() {
  /* The CBC probe is fed deliberate nonsense, so "live" for it means anything other than the
     refusal a null handle produces. The other two round-trip real data and must succeed. */
  return probe_gcm() == gcm::Error::ok && probe_mac() == gcm::Error::ok &&
         probe_cbc() != gcm::Error::openssl;
}

bool algorithms_released() {
  return probe_gcm() == gcm::Error::openssl && probe_mac() == gcm::Error::openssl &&
         probe_cbc() == gcm::Error::openssl;
}

int component_init() { return COMPONENT_REF(gcm).init(); }
int component_deinit() { return COMPONENT_REF(gcm).deinit(); }

}  // namespace gcm_adapter
