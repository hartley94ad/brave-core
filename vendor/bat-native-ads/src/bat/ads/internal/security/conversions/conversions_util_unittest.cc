/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/security/conversions/conversions_util.h"

#include "base/base64.h"
#include "bat/ads/internal/conversions/verifiable_conversion_info.h"
#include "bat/ads/internal/security/conversions/verifiable_conversion_envelope_info.h"
#include "testing/gtest/include/gtest/gtest.h"

// npm run test -- brave_unit_tests --filter=BatAds*

namespace ads {
namespace security {

TEST(BatAdsSecurityConversionsUtilsTest, EncryptAndEncodeShortMessage) {
  // Arrange
  const std::string advertiser_public_key =
      "ofIveUY/bM7qlL9eIkAv/xbjDItFs1xRTTYKRZZsPHI=";
  const std::string advertiser_secret_key =
      "Ete7+aKfrX25gt0eN4kBV1LqeF9YmB1go8OqnGXUGG4=";
  const std::string message = "shortmessage";

  VerifiableConversionInfo verifiable_conversion;
  verifiable_conversion.id = message;
  verifiable_conversion.public_key = advertiser_public_key;

  // Act
  VerifiableConversionEnvelopeInfo verifiable_conversion_envelope =
      EncryptAndEncode(verifiable_conversion);
  std::string result =
      DecodeAndDecrypt(verifiable_conversion_envelope, advertiser_secret_key);

  // Assert
  EXPECT_TRUE(result.empty());
}

TEST(BatAdsSecurityConversionsUtilsTest, EncryptAndEncodeLongMessage) {
  // Arrange
  const std::string advertiser_public_key =
      "ofIveUY/bM7qlL9eIkAv/xbjDItFs1xRTTYKRZZsPHI=";
  const std::string advertiser_secret_key =
      "Ete7+aKfrX25gt0eN4kBV1LqeF9YmB1go8OqnGXUGG4=";
  const std::string message = "thismessageistoolongthismessageistoolong";

  VerifiableConversionInfo verifiable_conversion;
  verifiable_conversion.id = message;
  verifiable_conversion.public_key = advertiser_public_key;

  // Act
  VerifiableConversionEnvelopeInfo verifiable_conversion_envelope =
      EncryptAndEncode(verifiable_conversion);
  std::string result =
      DecodeAndDecrypt(verifiable_conversion_envelope, advertiser_secret_key);

  // Assert
  EXPECT_TRUE(result.empty());
}

TEST(BatAdsSecurityConversionsUtilsTest, EncryptAndEncodeInvalidMessage) {
  // Arrange
  const std::string advertiser_public_key =
      "ofIveUY/bM7qlL9eIkAv/xbjDItFs1xRTTYKRZZsPHI=";
  const std::string advertiser_secret_key =
      "Ete7+aKfrX25gt0eN4kBV1LqeF9YmB1go8OqnGXUGG4=";
  const std::string message = "smart brown foxes 16";

  VerifiableConversionInfo verifiable_conversion;
  verifiable_conversion.id = message;
  verifiable_conversion.public_key = advertiser_public_key;

  // Act
  VerifiableConversionEnvelopeInfo verifiable_conversion_envelope =
      EncryptAndEncode(verifiable_conversion);
  std::string result =
      DecodeAndDecrypt(verifiable_conversion_envelope, advertiser_secret_key);

  // Assert
  EXPECT_TRUE(result.empty());
}

TEST(BatAdsSecurityConversionsUtilsTest, EncryptAndEncodeWithInvalidPublicKey) {
  // Arrange
  const std::string message = "smartbrownfoxes42";
  const std::string advertiser_public_key =
      "ofIveUY/bM7qlL9eIkAv/xbjDItFs1xRTTYK/INVALID";
  const std::string advertiser_secret_key =
      "Ete7+aKfrX25gt0eN4kBV1LqeF9YmB1go8OqnGXUGG4=";

  VerifiableConversionInfo verifiable_conversion;
  verifiable_conversion.id = message;
  verifiable_conversion.public_key = advertiser_public_key;

  // Act
  VerifiableConversionEnvelopeInfo verifiable_conversion_envelope =
      EncryptAndEncode(verifiable_conversion);
  std::string result =
      DecodeAndDecrypt(verifiable_conversion_envelope, advertiser_secret_key);

  // Assert
  EXPECT_TRUE(result.empty());
}

TEST(BatAdsSecurityConversionsUtilsTest, EncryptAndEncode) {
  // Arrange
  const std::string message = "smartbrownfoxes42";
  const std::string advertiser_public_key =
      "ofIveUY/bM7qlL9eIkAv/xbjDItFs1xRTTYKRZZsPHI=";
  const std::string advertiser_secret_key =
      "Ete7+aKfrX25gt0eN4kBV1LqeF9YmB1go8OqnGXUGG4=";

  VerifiableConversionInfo verifiable_conversion;
  verifiable_conversion.id = message;
  verifiable_conversion.public_key = advertiser_public_key;

  // Act
  VerifiableConversionEnvelopeInfo verifiable_conversion_envelope =
      EncryptAndEncode(verifiable_conversion);
  std::string result =
      DecodeAndDecrypt(verifiable_conversion_envelope, advertiser_secret_key);

  // Assert
  EXPECT_EQ(message, result);
}

}  // namespace security
}  // namespace ads
