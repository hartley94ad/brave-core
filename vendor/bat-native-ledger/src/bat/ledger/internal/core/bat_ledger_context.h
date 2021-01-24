/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_BAT_LEDGER_CONTEXT_H_
#define BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_BAT_LEDGER_CONTEXT_H_

#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "base/location.h"
#include "base/memory/weak_ptr.h"
#include "bat/ledger/ledger.h"
#include "bat/ledger/public/interfaces/ledger.mojom.h"

namespace ledger {

class LedgerImpl;
class LedgerClient;

class BATLedgerContext {
 public:
  using ComponentKey = unsigned;

  class Component : public base::SupportsWeakPtr<Component> {
   public:
    virtual ~Component();

    Component(const Component&) = delete;
    Component& operator=(const Component&) = delete;

   protected:
    explicit Component(BATLedgerContext* context);

    BATLedgerContext* context() { return context_; }

   private:
    // A pointer to the BATLedgerContext instance that owns this object
    BATLedgerContext* context_;
  };

  // NOTE: Values are based on the original logging design where each level from
  // 0 to 9 were assigned a specific subject matter. At some point in the future
  // these values can be renumbered.
  enum class LogLevel { kError = 0, kInfo = 1, kVerbose = 6, kFull = 9 };

  class LogStream {
   public:
    LogStream(BATLedgerContext* context,
              base::Location location,
              LogLevel log_level);

    LogStream(const LogStream&) = delete;
    LogStream& operator=(const LogStream&) = delete;

    LogStream(LogStream&& other);
    LogStream& operator=(LogStream&& other);

    ~LogStream();

    template <typename T>
    LogStream& operator<<(const T& value) {
      stream_ << value;
      return *this;
    }

   private:
    BATLedgerContext* context_;
    base::Location location_;
    LogLevel log_level_;
    std::ostringstream stream_;
    bool moved_ = false;
  };

  explicit BATLedgerContext(LedgerClient* ledger_client);
  explicit BATLedgerContext(LedgerImpl* ledger_impl);

  ~BATLedgerContext();

  BATLedgerContext(const BATLedgerContext&) = delete;
  BATLedgerContext& operator=(const BATLedgerContext&) = delete;

  LedgerClient* GetLedgerClient() const { return ledger_client_; }
  LedgerImpl* GetLedgerImpl() const { return ledger_impl_; }

  template <typename T>
  T* Get() {
    static_assert(std::is_base_of<Component, T>::value,
                  "Get<T> requires that T is a subclass of Component");
    auto iter = components_.find(T::kComponentKey);
    if (iter != components_.end())
      return reinterpret_cast<T*>(iter->second.get());

    std::unique_ptr<T> instance(new T(this));
    T* ptr = instance.get();
    components_[T::kComponentKey] = std::move(instance);
    return ptr;
  }

  template <typename T>
  void SetComponentForTesting(std::unique_ptr<T> component) {
    static_assert(std::is_base_of<Component, T>::value,
                  "SetComponentForTesting<T> requires that T is a subclass of "
                  "Component");
    components_[T::kComponentKey] = std::move(component);
  }

  template <typename T, typename... Args>
  auto StartTask(Args&&... args) {
    std::unique_ptr<T> instance(new T(this));
    T* ptr = instance.get();

    size_t key = std::hash<T*>()(ptr);
    tasks_[key] = std::move(instance);

    auto result = ptr->Start(std::forward<Args>(args)...);

    using CompleteType = typename decltype(result)::CompleteType;
    using ErrorType = typename decltype(result)::ErrorType;

    result.Listen(
        base::BindOnce(&BATLedgerContext::OnTaskFinished<CompleteType>,
                       weak_factory_.GetWeakPtr(), key),
        base::BindOnce(&BATLedgerContext::OnTaskFinished<ErrorType>,
                       weak_factory_.GetWeakPtr(), key));

    return result;
  }

  static ComponentKey ReserveComponentKey();

  LogStream Log(base::Location location, LogLevel log_level);
  LogStream LogError(base::Location location);
  LogStream LogInfo(base::Location location);
  LogStream LogVerbose(base::Location location);
  LogStream LogFull(base::Location location);

  template <typename T>
  const T& GetSettings() {
    switch (ledger::_environment) {
      case mojom::Environment::DEVELOPMENT:
        return T::kDevelopment;
      case mojom::Environment::STAGING:
        return T::kStaging;
      case mojom::Environment::PRODUCTION:
        return T::kProduction;
    }
  }

 private:
  template <typename T>
  void OnTaskFinished(size_t task_key, const T&) {
    tasks_.erase(task_key);
  }

  LedgerClient* ledger_client_;
  LedgerImpl* ledger_impl_ = nullptr;
  std::unordered_map<ComponentKey, std::unique_ptr<Component>> components_;
  std::unordered_map<std::size_t, std::unique_ptr<Component>> tasks_;
  base::WeakPtrFactory<BATLedgerContext> weak_factory_{this};
};

}  // namespace ledger

#endif  // BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_BAT_LEDGER_CONTEXT_H_
