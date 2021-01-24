/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_ASYNC_RESULT_H_
#define BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_ASYNC_RESULT_H_

#include <list>
#include <memory>
#include <type_traits>
#include <utility>

#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/optional.h"
#include "base/threading/sequenced_task_runner_handle.h"

namespace ledger {

struct AsyncResultVoidError {};

template <typename V, typename E = AsyncResultVoidError>
class AsyncResult {
 public:
  using CompleteType = V;
  using ErrorType = E;

  using CompleteCallback = base::OnceCallback<void(const V&)>;
  using ErrorCallback = base::OnceCallback<void(const E&)>;

  enum class State { kPending, kComplete, kError };

  void Listen(CompleteCallback on_complete, ErrorCallback on_error) {
    Listener listener = {.on_complete = std::move(on_complete),
                         .on_error = std::move(on_error),
                         .task_runner = base::SequencedTaskRunnerHandle::Get()};

    task_runner_->PostTask(FROM_HERE, base::BindOnce(AddListenerInTask, store_,
                                                     std::move(listener)));
  }

  void Listen(CompleteCallback on_complete) {
    static_assert(
        std::is_same<E, AsyncResultVoidError>::value,
        "Listen requires an error callback when an error type is specified");
    Listen(std::move(on_complete), base::DoNothing());
  }

  class Resolver {
   public:
    Resolver() {}
    void Complete(V&& value) { result_.Complete(std::move(value)); }
    void Error(E&& error) { result_.Error(std::move(error)); }
    AsyncResult result() const { return result_; }

   private:
    AsyncResult result_;
  };

 private:
  AsyncResult()
      : store_(new Store()),
        task_runner_(base::SequencedTaskRunnerHandle::Get()) {}

  struct Listener {
    CompleteCallback on_complete;
    ErrorCallback on_error;
    scoped_refptr<base::SequencedTaskRunner> task_runner;
  };

  struct Store {
    Store() {}
    State state = State::kPending;
    base::Optional<V> value;
    base::Optional<E> error;
    std::list<Listener> listeners;
  };

  void Complete(V&& value) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(SetCompleteInTask, store_, std::move(value)));
  }

  void Error(E&& error) {
    static_assert(!std::is_same<E, AsyncResultVoidError>::value,
                  "Cannot call Error when no error type is specified");
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(SetErrorInTask, store_, std::move(error)));
  }

  static void AddListenerInTask(std::shared_ptr<Store> store,
                                Listener listener) {
    switch (store->state) {
      case State::kComplete:
        listener.task_runner->PostTask(
            FROM_HERE, base::BindOnce(RunCompleteCallback, store,
                                      std::move(listener.on_complete)));
        break;
      case State::kError:
        listener.task_runner->PostTask(
            FROM_HERE, base::BindOnce(RunErrorCallback, store,
                                      std::move(listener.on_error)));
        break;
      case State::kPending:
        store->listeners.emplace_back(std::move(listener));
        break;
    }
  }

  static void SetCompleteInTask(std::shared_ptr<Store> store, V value) {
    if (store->state != State::kPending)
      return;

    store->state = State::kComplete;
    store->value = std::move(value);

    for (auto& listener : store->listeners) {
      listener.task_runner->PostTask(
          FROM_HERE, base::BindOnce(RunCompleteCallback, store,
                                    std::move(listener.on_complete)));
    }

    store->listeners.clear();
  }

  static void SetErrorInTask(std::shared_ptr<Store> store, E error) {
    if (store->state != State::kPending)
      return;

    store->state = State::kError;
    store->error = std::move(error);

    for (auto& listener : store->listeners) {
      listener.task_runner->PostTask(
          FROM_HERE, base::BindOnce(RunErrorCallback, store,
                                    std::move(listener.on_error)));
    }

    store->listeners.clear();
  }

  static void RunCompleteCallback(std::shared_ptr<Store> store,
                                  CompleteCallback on_complete) {
    DCHECK(store->value);
    std::move(on_complete).Run(*store->value);
  }

  static void RunErrorCallback(std::shared_ptr<Store> store,
                               ErrorCallback on_error) {
    DCHECK(store->error);
    std::move(on_error).Run(*store->error);
  }

  std::shared_ptr<Store> store_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

}  // namespace ledger

#endif  // BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_ASYNC_RESULT_H_
