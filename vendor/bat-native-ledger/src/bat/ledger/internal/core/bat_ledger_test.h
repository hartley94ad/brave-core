/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_BAT_LEDGER_TEST_H_
#define BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_BAT_LEDGER_TEST_H_

#include <string>

#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "bat/ledger/internal/core/bat_ledger_context.h"
#include "bat/ledger/internal/core/test_ledger_client.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace ledger {

class BATLedgerTest : public testing::Test {
 protected:
  base::test::TaskEnvironment* task_environment() { return &task_environment_; }
  BATLedgerContext* context() { return &context_; }

  TestLedgerClient* GetTestLedgerClient() { return &client_; }

  void AddNetworkResultForTesting(const std::string& url,
                                  mojom::UrlMethod method,
                                  mojom::UrlResponsePtr response);

  void SetLogCallbackForTesting(TestLedgerClient::LogCallback callback);

 private:
  base::test::TaskEnvironment task_environment_;
  TestLedgerClient client_;
  BATLedgerContext context_{&client_};
};

}  // namespace ledger

#endif  // BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_BAT_LEDGER_TEST_H_
