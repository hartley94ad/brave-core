/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/tokens/redeem_unblinded_token/user_data/confirmation_conversion_dto_user_data.h"

#include <utility>

namespace ads {
namespace dto {
namespace user_data {

base::DictionaryValue GetConversion(
    const ConversionQueueItemList& conversion_queue_items) {
  base::DictionaryValue user_data;

  base::DictionaryValue dictionary;
  dictionary.SetKey("alg", base::Value("alg"));
  dictionary.SetKey("ciphertext", base::Value("ciphertext"));
  dictionary.SetKey("epk", base::Value("epk"));
  dictionary.SetKey("nonce", base::Value("nonce"));

  user_data.SetKey("conversionEnvelope", std::move(dictionary));

  return user_data;
}

}  // namespace user_data
}  // namespace dto
}  // namespace ads
