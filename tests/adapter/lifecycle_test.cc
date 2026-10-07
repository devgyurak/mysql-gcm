/* SPDX-License-Identifier: GPL-2.0-only */
/* The component's install and uninstall paths, driven through mysql_component_t against stub
 * services (service_stubs.h).
 *
 * This is the layer the project did not have: tests/unit covers the server-independent core,
 * the integration and MTR suites cover SQL behaviour against a real server, and nothing
 * covered registration order, rollback, or what happens to the fetched algorithms when a
 * rollback is refused. Two defects escaped there and were caught by review rather than by a
 * test — unregister_first() returning void, and sysvar_unregister()'s result being discarded
 * — which is what this file exists to stop repeating.
 *
 * The algorithms are read through gcm::encrypt_random, not a test-only accessor, so nothing
 * here required a seam in src/ (architecture rule §6, enforced by check-architecture.py).
 */

#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <mysql/udf_registration_types.h>

#include "envelope.h"
#include "service_stubs.h"
#include "sysvar.h"

namespace {

using gcm_adapter::algorithms_live;
using gcm_adapter::algorithms_released;
using gcm_adapter::component_deinit;
using gcm_adapter::component_init;
using gcm_adapter::details_for;
using gcm_adapter::fail;
using gcm_adapter::FailureRule;
using gcm_adapter::min_key_bytes_is_registered;
using gcm_adapter::registered_udfs;
using gcm_adapter::sysvar_is_registered;

const std::vector<std::string> kAllUdfs = {"gcm_encrypt", "gcm_encrypt_det", "gcm_decrypt"};
constexpr const char *kStrict = "gcm.strict";
constexpr const char *kFloor = "gcm.min_key_bytes";
/* min_key_bytes() reads GLOBAL on every version, but through a different service:
   9.x deprecates get_variable() and -Werror makes using it a build failure there. */
#if GCM_HAS_SESSION_SYSVAR
constexpr const char *kFloorReadMethod = "variable_reader_get";
#else
constexpr const char *kFloorReadMethod = "get_variable";
#endif

class Lifecycle : public ::testing::Test {
 protected:
  void SetUp() override {
    gcm_adapter::install();
    gcm_adapter::reset();
    gcm_adapter::forget_registrations();
  }

  /* TearDown, not SetUp, is what gets every case back to "nothing registered and the
     algorithms released" — the first case relies on static initialisation for that.
     Clearing the failure rules first is load-bearing: without it a case that injected a
     refusal would have its teardown refused too, the algorithms would survive, and the next
     case could pass on a handle it never fetched. */
  void TearDown() override {
    gcm_adapter::reset();
    component_deinit();
    gcm_adapter::reset();
    gcm_adapter::forget_registrations();
    ASSERT_TRUE(algorithms_released()) << "teardown left algorithms fetched";
  }
};

TEST_F(Lifecycle, GivenEveryServiceSucceeds_WhenInit_ThenAllUdfsThenTheSysvarAreRegistered) {
  // Given: no failures injected

  // When
  const int status = component_init();

  // Then
  EXPECT_EQ(status, 0);
  EXPECT_EQ(details_for("udf_register"), kAllUdfs);
  EXPECT_EQ(details_for("register_variable"), (std::vector<std::string>{kStrict, kFloor}));
  EXPECT_EQ(registered_udfs(), std::set<std::string>(kAllUdfs.begin(), kAllUdfs.end()));
  EXPECT_TRUE(sysvar_is_registered());
  EXPECT_TRUE(min_key_bytes_is_registered());
  EXPECT_TRUE(algorithms_live());
}

TEST_F(Lifecycle, GivenEveryServiceSucceeds_WhenInit_ThenTheSysvarIsRegisteredAfterTheUdfs) {
  // Given: no failures injected

  // When
  const int status = component_init();

  // Then: the variable comes last, so a udf_register failure rolls back with nothing in the
  //       system variable dictionary to leave behind (design A9)
  ASSERT_EQ(status, 0);
  const std::vector<gcm_adapter::Call> &calls = gcm_adapter::calls();
  ASSERT_FALSE(calls.empty());
  EXPECT_EQ(calls.back().method, "register_variable");
}

TEST_F(Lifecycle, GivenTheSecondUdfFailsToRegister_WhenInit_ThenTheFirstIsUnregistered) {
  // Given
  fail(FailureRule{"udf_register", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_init();

  // Then
  EXPECT_EQ(status, 1);
  EXPECT_EQ(details_for("udf_unregister"), std::vector<std::string>{"gcm_encrypt"});
  EXPECT_TRUE(details_for("register_variable").empty());
  EXPECT_TRUE(registered_udfs().empty());
  EXPECT_FALSE(sysvar_is_registered());
  EXPECT_FALSE(min_key_bytes_is_registered());
}

TEST_F(Lifecycle, GivenAUdfFailsAndRollbackSucceeds_WhenInit_ThenTheAlgorithmsAreReleased) {
  // Given
  fail(FailureRule{"udf_register", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_init();

  // Then: nothing can reach them any more, so holding them would be a leak
  ASSERT_EQ(status, 1);
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenARefusedUnregisterDuringRollback_WhenInit_ThenTheAlgorithmsAreKept) {
  // Given: the second function cannot register, and unregistering the first is refused
  //        because it is still in use
  fail(FailureRule{"udf_register", "gcm_encrypt_det", 1, true});
  fail(FailureRule{"udf_unregister", "gcm_encrypt", 1, true});

  // When
  const int status = component_init();

  // Then: gcm_encrypt is still callable, so freeing the algorithms underneath it would add a
  //       second fault to a failed install
  ASSERT_EQ(status, 1);
  EXPECT_TRUE(algorithms_live());
}

TEST_F(Lifecycle, GivenAnUnregisterThatReportsNotPresent_WhenInit_ThenTheAlgorithmsAreReleased) {
  // Given: the unregister returns failure but reports the function was not there, which means
  //        it is gone rather than in use
  fail(FailureRule{"udf_register", "gcm_encrypt_det", 1, true});
  fail(FailureRule{"udf_unregister", "gcm_encrypt", 1, false});

  // When
  const int status = component_init();

  // Then
  ASSERT_EQ(status, 1);
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenTheSysvarFailsToRegister_WhenInit_ThenEveryUdfIsUnregistered) {
  // Given
  fail(FailureRule{"register_variable", kStrict, 1, true});

  // When
  const int status = component_init();

  // Then
  EXPECT_EQ(status, 1);
  EXPECT_EQ(details_for("udf_unregister"), kAllUdfs);
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenAFunctionStillInUse_WhenDeinit_ThenTheUnloadIsRefused) {
  // Given: an installed component whose second function is in use
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"udf_unregister", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_deinit();

  // Then
  EXPECT_EQ(status, 1);
  EXPECT_TRUE(algorithms_live());
}

TEST_F(Lifecycle, GivenAFunctionStillInUse_WhenDeinit_ThenTheEarlierOnesComeBack) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"udf_unregister", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_deinit();

  // Then: a refused UNINSTALL must not leave a half-working component
  ASSERT_EQ(status, 1);
  EXPECT_EQ(details_for("udf_register"), std::vector<std::string>{"gcm_encrypt"});
}

TEST_F(Lifecycle, GivenTheSysvarCannotBeUnregistered_WhenDeinit_ThenTheAlgorithmsAreKept) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"unregister_variable", kStrict, 1, true});

  // When
  const int status = component_deinit();

  // Then: the variable still points at this component's storage
  EXPECT_EQ(status, 1);
  EXPECT_TRUE(algorithms_live());
  EXPECT_EQ(details_for("udf_register"), kAllUdfs);
}

TEST_F(Lifecycle, GivenTheVariableIsNotRegisteredYet_WhenStrictIsQueried_ThenStrictIsOn) {
  // Given: the component is not installed, so gcm.strict does not exist. This is the window
  //        design A9 opens by registering the variable after the functions, and the whole
  //        justification for that ordering is that a read in it fails closed.

  // When
  const bool strict = gcm::strict_enabled();

  // Then: ON. A false here would turn a tag mismatch into NULL for any call that landed in
  //       the window, which is the one direction this must never get wrong.
  EXPECT_TRUE(strict);
}

TEST_F(Lifecycle, GivenTheVariableReadFails_WhenStrictIsQueried_ThenStrictIsOn) {
  // Given: installed, but the service refuses to hand the value over
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"get_variable", "", 0, true});
  fail(FailureRule{"variable_reader_get", "", 0, true});

  // When
  const bool strict = gcm::strict_enabled();

  // Then
  EXPECT_TRUE(strict);
}

TEST_F(Lifecycle, GivenTheComponentIsInstalled_WhenStrictIsQueried_ThenItGoesThroughAService) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();

  // When
  (void)gcm::strict_enabled();

  // Then: the value came from a service that holds the server's lock, not from the
  //       registration's storage byte. Reading g_strict directly was the data race fixed
  //       earlier, and without this the two are indistinguishable from outside.
  const size_t reads =
      details_for("get_variable").size() + details_for("variable_reader_get").size();
  EXPECT_EQ(reads, 1u);
}

#if GCM_HAS_SESSION_SYSVAR
TEST_F(Lifecycle, GivenSessionScopeExists_WhenStrictIsQueried_ThenTheReadAsksForSession) {
  // Given: a major where a component sysvar has session scope (design A5)
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();

  // When
  (void)gcm::strict_enabled();

  // Then: SESSION, not GLOBAL. Asking for GLOBAL here would silently ignore
  //       SET SESSION gcm.strict on the one major where it works, with no error to notice.
  EXPECT_EQ(gcm_adapter::extra_for("variable_reader_get"), "SESSION");
}
#endif

TEST_F(Lifecycle, GivenAnUnregisterThatReportsNotPresent_WhenDeinit_ThenTheUnloadSucceeds) {
  // Given: installed, and one unregister fails while reporting the function was not there —
  //        which means it is gone, not in use
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"udf_unregister", "gcm_encrypt_det", 1, false});

  // When
  const int status = component_deinit();

  // Then: the unload is not refused, and nothing was put back
  EXPECT_EQ(status, 0);
  EXPECT_TRUE(details_for("udf_register").empty());
  EXPECT_TRUE(registered_udfs().empty());
}

TEST_F(Lifecycle, GivenReRegistrationAlsoFails_WhenDeinit_ThenTheUnloadIsStillRefused) {
  // Given: installed; the second function is in use, and putting the first one back fails too
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"udf_unregister", "gcm_encrypt_det", 1, true});
  fail(FailureRule{"udf_register", "gcm_encrypt", 1, true});

  // When
  const int status = component_deinit();

  // Then: still refused, and the component is left incomplete — gcm_encrypt did not come back.
  //       There is no logging service here, so this state has no signal beyond the refusal.
  EXPECT_EQ(status, 1);
  EXPECT_EQ(registered_udfs(), std::set<std::string>({"gcm_encrypt_det", "gcm_decrypt"}));
  EXPECT_TRUE(algorithms_live());
}

TEST_F(Lifecycle, GivenTheSysvarFailsAndAnUnregisterIsRefused_WhenInit_ThenTheAlgorithmsAreKept) {
  // Given: every function registers, the variable does not, and rolling the functions back is
  //        refused because one is in use
  fail(FailureRule{"register_variable", kStrict, 1, true});
  fail(FailureRule{"udf_unregister", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_init();

  // Then: gcm_encrypt_det is still callable, so the algorithms it needs must survive. Without
  //       this case the conditional on that path could be dropped entirely and nothing noticed.
  ASSERT_EQ(status, 1);
  EXPECT_EQ(registered_udfs(), std::set<std::string>{"gcm_encrypt_det"});
  EXPECT_TRUE(algorithms_live());
}

TEST_F(Lifecycle, GivenAFunctionStillInUse_WhenDeinit_ThenTheVariableIsStillRegistered) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"udf_unregister", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_deinit();

  // Then: the functions are handled before the variable, so a refusal happens while gcm.strict
  //       is still there. Unregistering it first would leave a loaded component with no
  //       variable — a half-working install that only a restart repairs (design A9).
  ASSERT_EQ(status, 1);
  EXPECT_TRUE(sysvar_is_registered());
  EXPECT_TRUE(details_for("unregister_variable").empty());
}

TEST_F(Lifecycle, GivenEverythingUnregisters_WhenDeinit_ThenTheVariableGoesLast) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();

  // When
  const int status = component_deinit();

  // Then: the whole sequence, not just its contents. Checking only which calls happened cannot
  //       see the variable moved to the front, which is exactly the mutation that slipped past
  //       an earlier version of this file.
  ASSERT_EQ(status, 0);
  EXPECT_EQ(gcm_adapter::call_sequence(),
            std::vector<std::string>(
                {"udf_unregister:gcm_encrypt", "udf_unregister:gcm_encrypt_det",
                 "udf_unregister:gcm_decrypt", "unregister_variable:gcm.min_key_bytes",
                 "unregister_variable:gcm.strict"}));
}

TEST_F(Lifecycle, GivenEverythingUnregisters_WhenDeinit_ThenTheAlgorithmsAreReleased) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();

  // When
  const int status = component_deinit();

  // Then
  EXPECT_EQ(status, 0);
  EXPECT_EQ(details_for("udf_unregister"), kAllUdfs);
  EXPECT_EQ(details_for("unregister_variable"), (std::vector<std::string>{kFloor, kStrict}));
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenTheFloorFailsToRegister_WhenInit_ThenStrictIsRolledBackToo) {
  // Given: gcm.strict registers, gcm.min_key_bytes does not (design A10)
  fail(FailureRule{"register_variable", kFloor, 1, true});

  // When
  const int status = component_init();

  // Then: neither variable survives. One left behind would sit in the server's
  //       dictionary pointing into memory the loader is about to unmap, and a
  //       variable is reachable by enumeration alone (design A9).
  EXPECT_EQ(status, 1);
  EXPECT_FALSE(sysvar_is_registered());
  EXPECT_FALSE(min_key_bytes_is_registered());
  EXPECT_TRUE(registered_udfs().empty());
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenTheFloorFailsAndStrictWillNotUnregister_WhenInit_ThenAlgorithmsAreKept) {
  // Given
  fail(FailureRule{"register_variable", kFloor, 1, true});
  fail(FailureRule{"unregister_variable", kStrict, 1, true});

  // When
  const int status = component_init();

  // Then: a variable survived the rollback, so the handles it may still reach
  //       stay alive — the same position deinit takes (design A9)
  EXPECT_EQ(status, 1);
  EXPECT_TRUE(sysvar_is_registered());
  EXPECT_TRUE(algorithms_live());
}

// --- gcm.min_key_bytes (design A10) ------------------------------------------

TEST_F(Lifecycle, GivenANonDefaultFloorAndStrictRefuses_WhenDeinit_ThenThePolicyNeverWidens) {
  // Given: a server booted with a lower floor than the one now in force --
  //        loose_gcm.min_key_bytes=16 in my.cnf, raised to 32 at runtime
  gcm_adapter::set_startup_option(kFloor, "16");
  ASSERT_EQ(component_init(), 0);
  ASSERT_EQ(gcm::min_key_bytes(), gcm::kKeyLen128) << "the startup option must take effect";
  gcm_adapter::set_sysvar_value(kFloor, "32");  // SET GLOBAL gcm.min_key_bytes = 32
  ASSERT_EQ(gcm::min_key_bytes(), gcm::kKeyLen256);
  fail(FailureRule{"unregister_variable", kStrict, 1, true});

  // When: the uninstall is refused after the floor has already come out
  const int refused = component_deinit();

  // Then: the effective policy at that moment is 32, not the 16 the startup
  //       option would restore. register_variable re-applies argv_cached plus the
  //       persisted variables, so re-registering the floor here would hand an
  //       operator back a policy they had deliberately raised, and AES-128 writes
  //       with it. An absent floor reads as 32 instead: strictly narrower.
  EXPECT_EQ(refused, 1);
  EXPECT_FALSE(min_key_bytes_is_registered());
  EXPECT_EQ(gcm::min_key_bytes(), gcm::kKeyLen256);
}

TEST_F(Lifecycle, GivenStrictWillNotUnregister_WhenDeinit_ThenRetryStillCompletes) {
  // Given: an install, and a server that refuses the first unregister of gcm.strict
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"unregister_variable", kStrict, 1, true});

  // When: the first uninstall is attempted and then retried
  const int refused = component_deinit();
  gcm_adapter::reset();  // the refusal was a one-shot rule
  const int retried = component_deinit();

  // Then: the first is refused and the retry succeeds. What makes the retry work
  //       is the state flags, not a re-registration: the floor is already gone, and
  //       unregistering a variable the server does not have is itself a failure, so
  //       an unguarded retry would fail forever.
  EXPECT_EQ(refused, 1);
  EXPECT_EQ(retried, 0);
  EXPECT_FALSE(sysvar_is_registered());
  EXPECT_FALSE(min_key_bytes_is_registered());
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenTheFloorWillNotUnregister_WhenDeinit_ThenNothingIsRemovedAndRetryWorks) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();
  fail(FailureRule{"unregister_variable", kFloor, 1, true});

  // When
  const int refused = component_deinit();
  gcm_adapter::reset();
  const int retried = component_deinit();

  // Then: the floor is removed first precisely so a refusal there leaves the
  //       component exactly as it was
  EXPECT_EQ(refused, 1);
  EXPECT_EQ(retried, 0);
  EXPECT_TRUE(algorithms_released());
}

TEST_F(Lifecycle, GivenTheFloorCannotBeRead_WhenAUdfInitRuns_ThenItFailsClosedTo32) {
  // Given: the read of gcm.min_key_bytes fails
  ASSERT_EQ(component_init(), 0);
  fail(FailureRule{kFloorReadMethod, kFloor, 0, true});

  // When
  const size_t floor = gcm::min_key_bytes();

  // Then: the strictest floor, so a lost setting can never widen what the server
  //       accepts. Answering 16 here would silently allow AES-128 everywhere.
  EXPECT_EQ(floor, gcm::kKeyLen256);
}

class FloorValue : public ::testing::TestWithParam<const char *> {
 protected:
  void SetUp() override {
    gcm_adapter::install();
    gcm_adapter::reset();
    gcm_adapter::forget_registrations();
    ASSERT_EQ(component_init(), 0);
  }
  void TearDown() override {
    gcm_adapter::reset();
    component_deinit();
    gcm_adapter::reset();
    gcm_adapter::forget_registrations();
  }
};

TEST_P(FloorValue, GivenAValueTheComponentCannotTrust_WhenRead_ThenItFallsBackTo32) {
  // Given
  gcm_adapter::set_sysvar_value(kFloor, GetParam());

  // When
  const size_t floor = gcm::min_key_bytes();

  // Then: anything that is not a plain decimal inside the registered range is
  //       refused rather than guessed at
  EXPECT_EQ(floor, gcm::kKeyLen256);
}

INSTANTIATE_TEST_SUITE_P(Untrusted, FloorValue,
                         ::testing::Values("", " ", "notanumber", "16x", "0x10", "-16", "8", "48",
                                           "99999999999999999999"),
                         [](const ::testing::TestParamInfo<const char *> &info) {
                           return "case" + std::to_string(info.index);
                         });

TEST_F(Lifecycle, GivenTheFloorIsLowered_WhenRead_ThenTheValueIsHonoured) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::set_sysvar_value(kFloor, "16");

  // When
  const size_t floor = gcm::min_key_bytes();

  // Then: the fallback is for untrusted input, not for every read
  EXPECT_EQ(floor, gcm::kKeyLen128);
}

#if GCM_HAS_SESSION_SYSVAR
TEST_F(Lifecycle, GivenTheReaderIsUsed_WhenTheFloorIsRead_ThenItAsksForGlobalScope) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::reset();

  // When
  (void)gcm::min_key_bytes();

  // Then: GLOBAL, not SESSION. The floor is an administrator policy, and reading it
  //       per session would make it something a caller could set for itself —
  //       which is exactly what design A10 says it must not be.
  EXPECT_EQ(gcm_adapter::extra_for("variable_reader_get"), "GLOBAL");
}
#endif

}  // namespace

/* ---- design A11: the per-UDF_INIT crypto sessions ------------------------------------
 *
 * The amendment rests on one `UDF_INIT` owning one state that nothing else touches. These
 * cases drive the real UDF entry points through the stub services and pin that: two items
 * get two states, an item's state goes away in its deinit, and a value sealed by one item
 * opens through another item's reused context, twice, byte for byte. */

extern "C" {
bool gcm_encrypt_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_encrypt_det_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                          unsigned char *is_null, unsigned char *error);
void gcm_encrypt_det_deinit(UDF_INIT *initid);
bool gcm_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_decrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                      unsigned char *is_null, unsigned char *error);
void gcm_decrypt_deinit(UDF_INIT *initid);
}

namespace {

/* A two-argument call (value, key) with the fixture key: enough for init and one row. */
struct TwoArgs {
  UDF_ARGS args{};
  Item_result types[2] = {STRING_RESULT, STRING_RESULT};
  char *values[2] = {nullptr, nullptr};
  unsigned long lengths[2] = {0, 0};
  char maybe_null[2] = {0, 0};

  TwoArgs(const void *value, size_t value_len, const void *key, size_t key_len) {
    args.arg_count = 2;
    args.arg_type = types;
    args.args = values;
    args.lengths = lengths;
    args.maybe_null = maybe_null;
    values[0] = const_cast<char *>(static_cast<const char *>(value));
    lengths[0] = static_cast<unsigned long>(value_len);
    values[1] = const_cast<char *>(static_cast<const char *>(key));
    lengths[1] = static_cast<unsigned long>(key_len);
  }
};

const unsigned char kA11Key[gcm::kKeyLen256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
const char kA11Name[] = "\xed\x99\x8d\xea\xb8\xb8\xeb\x8f\x99";  // 홍길동

TEST_F(Lifecycle, GivenTwoDecryptItems_WhenBothInit_ThenEachOwnsItsOwnStateUntilItsDeinit) {
  // Given
  ASSERT_EQ(component_init(), 0);
  TwoArgs args(kA11Name, sizeof(kA11Name) - 1, kA11Key, sizeof(kA11Key));
  char message[512] = {};
  UDF_INIT first{};
  UDF_INIT second{};

  // When
  const bool first_failed = gcm_decrypt_init(&first, &args.args, message);
  const bool second_failed = gcm_decrypt_init(&second, &args.args, message);

  // Then: two items, two states, and a deinit releases only its own
  EXPECT_FALSE(first_failed) << message;
  EXPECT_FALSE(second_failed) << message;
  EXPECT_NE(first.ptr, nullptr);
  EXPECT_NE(second.ptr, nullptr);
  EXPECT_NE(first.ptr, second.ptr);
  gcm_decrypt_deinit(&first);
  EXPECT_EQ(first.ptr, nullptr);
  EXPECT_NE(second.ptr, nullptr);
  gcm_decrypt_deinit(&second);
  EXPECT_EQ(second.ptr, nullptr);
}

TEST_F(Lifecycle, GivenAValueSealedByOneItem_WhenAnotherItemOpensItTwice_ThenBothOpensMatch) {
  // Given: one deterministic item seals the name, one decrypt item will open it
  ASSERT_EQ(component_init(), 0);
  char message[512] = {};
  TwoArgs seal_args(kA11Name, sizeof(kA11Name) - 1, kA11Key, sizeof(kA11Key));
  UDF_INIT sealer{};
  ASSERT_FALSE(gcm_encrypt_det_init(&sealer, &seal_args.args, message)) << message;
  unsigned long envelope_len = 0;
  unsigned char is_null = 0;
  unsigned char error = 0;
  const char *envelope =
      gcm_encrypt_det_udf(&sealer, &seal_args.args, nullptr, &envelope_len, &is_null, &error);
  ASSERT_NE(envelope, nullptr);
  ASSERT_EQ(error, 0);
  const std::string sealed(envelope, envelope_len);
  gcm_encrypt_det_deinit(&sealer);

  TwoArgs open_args(sealed.data(), sealed.size(), kA11Key, sizeof(kA11Key));
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_init(&opener, &open_args.args, message)) << message;

  // When: the same item opens the same envelope twice — the second call is the reused path
  unsigned long first_len = 0;
  const char *first =
      gcm_decrypt_udf(&opener, &open_args.args, nullptr, &first_len, &is_null, &error);
  const std::string first_plain(first != nullptr ? first : "", first != nullptr ? first_len : 0);
  unsigned long second_len = 0;
  const char *second =
      gcm_decrypt_udf(&opener, &open_args.args, nullptr, &second_len, &is_null, &error);

  // Then
  EXPECT_EQ(error, 0);
  EXPECT_EQ(is_null, 0);
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(first_plain, std::string(kA11Name, sizeof(kA11Name) - 1));
  EXPECT_EQ(std::string(second, second_len), first_plain);
  gcm_decrypt_deinit(&opener);
}

}  // namespace

namespace {

/* One gcm_decrypt item over three rows: good, tampered, good. Under strict=OFF the server
   gets plaintext, NULL, plaintext from the same UDF_INIT — the reused context must recover
   from the bad tag on the row after it (design A11). */
TEST_F(Lifecycle, GivenStrictOffAndOneItem_WhenRowsAreGoodBadGood_ThenPlainNullPlain) {
  // Given
  ASSERT_EQ(component_init(), 0);
  gcm_adapter::set_sysvar_value("gcm.strict", "OFF");
  char message[512] = {};
  TwoArgs seal_args(kA11Name, sizeof(kA11Name) - 1, kA11Key, sizeof(kA11Key));
  UDF_INIT sealer{};
  ASSERT_FALSE(gcm_encrypt_det_init(&sealer, &seal_args.args, message)) << message;
  unsigned long envelope_len = 0;
  unsigned char is_null = 0;
  unsigned char error = 0;
  const char *envelope =
      gcm_encrypt_det_udf(&sealer, &seal_args.args, nullptr, &envelope_len, &is_null, &error);
  ASSERT_NE(envelope, nullptr);
  const std::string good(envelope, envelope_len);
  gcm_encrypt_det_deinit(&sealer);
  std::string bad = good;
  bad.back() = static_cast<char>(bad.back() ^ 0x01);

  TwoArgs good_row(good.data(), good.size(), kA11Key, sizeof(kA11Key));
  TwoArgs bad_row(bad.data(), bad.size(), kA11Key, sizeof(kA11Key));
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_init(&opener, &good_row.args, message)) << message;
  const std::string name(kA11Name, sizeof(kA11Name) - 1);

  // When: three rows through the one item
  unsigned long len1 = 0, len2 = 0, len3 = 0;
  unsigned char null1 = 0, null2 = 0, null3 = 0;
  unsigned char err1 = 0, err2 = 0, err3 = 0;
  const char *r1 = gcm_decrypt_udf(&opener, &good_row.args, nullptr, &len1, &null1, &err1);
  const std::string first(r1 != nullptr ? r1 : "", r1 != nullptr ? len1 : 0);
  const char *r2 = gcm_decrypt_udf(&opener, &bad_row.args, nullptr, &len2, &null2, &err2);
  const char *r3 = gcm_decrypt_udf(&opener, &good_row.args, nullptr, &len3, &null3, &err3);
  const std::string third(r3 != nullptr ? r3 : "", r3 != nullptr ? len3 : 0);

  // Then: plaintext, NULL without an error, plaintext
  EXPECT_EQ(first, name);
  EXPECT_EQ(null1, 0);
  EXPECT_EQ(err1, 0);
  EXPECT_EQ(r2, nullptr);
  EXPECT_EQ(null2, 1);
  EXPECT_EQ(err2, 0);
  EXPECT_EQ(third, name);
  EXPECT_EQ(null3, 0);
  EXPECT_EQ(err3, 0);
  gcm_decrypt_deinit(&opener);
}

}  // namespace
