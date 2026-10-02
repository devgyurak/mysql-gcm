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
using gcm_adapter::registered_udfs;
using gcm_adapter::sysvar_is_registered;

const std::vector<std::string> kAllUdfs = {"gcm_encrypt", "gcm_encrypt_det", "gcm_decrypt"};
constexpr const char *kStrict = "gcm.strict";

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
  EXPECT_EQ(details_for("register_variable"), std::vector<std::string>{kStrict});
  EXPECT_EQ(registered_udfs(), std::set<std::string>(kAllUdfs.begin(), kAllUdfs.end()));
  EXPECT_TRUE(sysvar_is_registered());
  EXPECT_TRUE(algorithms_live());
}

TEST_F(Lifecycle, GivenTheSecondUdfFailsToRegister_WhenInit_ThenTheFirstIsUnregistered) {
  // Given
  fail(FailureRule{"udf_register", "gcm_encrypt_det", 1, true});

  // When
  const int status = component_init();

  // Then
  EXPECT_EQ(status, 1);
  EXPECT_EQ(details_for("udf_unregister"), std::vector<std::string>{"gcm_encrypt"});
  EXPECT_TRUE(registered_udfs().empty());
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
  EXPECT_EQ(
      gcm_adapter::call_sequence(),
      std::vector<std::string>({"udf_unregister:gcm_encrypt", "udf_unregister:gcm_encrypt_det",
                                "udf_unregister:gcm_decrypt", "unregister_variable:gcm.strict"}));
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
  EXPECT_EQ(details_for("unregister_variable"), std::vector<std::string>{kStrict});
  EXPECT_TRUE(algorithms_released());
}

}  // namespace
