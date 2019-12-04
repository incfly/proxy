/* Copyright 2018 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>

#include "common/common/logger.h"
#include "common/http/utility.h"
#include "extensions/filters/http/well_known_names.h"

#include "src/envoy/http/authnv2/filter.h"
#include "src/envoy/utils/authn.h"
#include "src/envoy/utils/filter_names.h"
#include "src/envoy/utils/utils.h"

#include "absl/strings/match.h"
#include "absl/strings/str_split.h"

#include "common/json/json_loader.h"
#include "google/protobuf/struct.pb.h"
#include "include/istio/utils/attribute_names.h"
#include "src/envoy/http/jwt_auth/jwt.h"

namespace Envoy {
namespace Http {
namespace Istio {
namespace AuthN {

namespace {

// The JWT audience key name.
static const std::string kJwtAudienceKey = "aud";
// The JWT issuer key name.
static const std::string kJwtIssuerKey = "iss";
// The JWT subject key name.
static const std::string kJwtSubjectKey = "sub";
// The JWT authorized presenter key name.
static const std::string kJwtPresenterKey = "azp";
// The key name for the original claims in an exchanged token.
static const std::string kExchangedTokenOriginalPayload = "original_claims";

// Helper function to set a key/value pair into Struct.
void setKeyValue(ProtobufWkt::Struct& data, const std::string& key,
                 const std::string& value) {
  (*data.mutable_fields())[key].set_string_value(value);
}

// Returns true if the peer identity can be extracted from the underying
// certificate used for mTLS.
bool ProcessMtls(const Network::Connection* connection,
                 ProtobufWkt::Struct& authn_data) {
  std::string peer_principle;
  if (connection->ssl() == nullptr ||
      !connection->ssl()->peerCertificatePresented()) {
    return false;
  }
  Utils::GetPrincipal(connection, true, &peer_principle);
  if (peer_principle == "") {
    return false;
  }
  setKeyValue(authn_data, istio::utils::AttributeName::kSourcePrincipal,
              peer_principle);
  return true;
}

const std::string getClaimValue(const ProtobufWkt::Struct& claim_structs,
                                const std::string& key) {
  const auto& claim_fields = claim_structs.fields();
  if (claim_fields.find(key) == claim_fields.end()) {
    return "";
  }
  // Try string_value first.
  const auto& value = claim_fields.at(key);
  const std::string& str_val = value.string_value();
  if (str_val != "") {
    return str_val;
  }
  // Try list_string second.
  const auto& values = value.list_value().values();
  if (!values.empty()) {
    return values[0].string_value();
  }
  return "";
}

}  // namespace

// Returns true if the attribute populated to authn filter succeeds.
// Envoy jwt filter already set each claim values into the struct.
// https://github.com/envoyproxy/envoy/blob/master/source/extensions/filters/http/jwt_authn/verifier.cc#L120
bool AuthnV2Filter::processJwt(const ProtobufWkt::Struct& claim_structs,
                               ProtobufWkt::Struct& authn_data) {
  ENVOY_LOG(debug, "processJwt the original claim data {}\n",
            claim_structs.DebugString());

  // request.auth.principal
  const std::string iss = getClaimValue(claim_structs, kJwtIssuerKey);
  const std::string sub = getClaimValue(claim_structs, kJwtSubjectKey);
  if (!iss.empty() && !sub.empty()) {
    setKeyValue(authn_data, istio::utils::AttributeName::kRequestAuthPrincipal,
                iss + "/" + sub);
  }

  const std::string azp = getClaimValue(claim_structs, kJwtPresenterKey);
  if (!azp.empty()) {
    setKeyValue(authn_data, istio::utils::AttributeName::kRequestAuthPresenter,
                azp);
  }

  // request.auth.audiences
  const std::string aud = getClaimValue(claim_structs, kJwtAudienceKey);
  if (!aud.empty()) {
    setKeyValue(authn_data, istio::utils::AttributeName::kRequestAuthAudiences,
                aud);
  }

  // request.auth.claims, all claims must be encoded as list of strings.
  ProtobufWkt::Struct claim_as_list;
  for (const auto& field : claim_structs.fields()) {
    const std::string& key = field.first;
    const auto& val = field.second;
    ProtobufWkt::Value::KindCase kind = val.kind_case();
    ProtobufWkt::Value val_as_list;
    switch (kind) {
      case ProtobufWkt::Value::kListValue:
        (*claim_as_list.mutable_fields())[key] = val;
        break;
      default:
        if (!val.string_value().empty()) {
          val_as_list.mutable_list_value()->add_values()->set_string_value(
              val.string_value());
          (*claim_as_list.mutable_fields())[key] = val_as_list;
        }
    }
  }
  (*(*authn_data
          .mutable_fields())[istio::utils::AttributeName::kRequestAuthClaims]
        .mutable_struct_value())
      .MergeFrom(claim_as_list);

  // request.auth.raw_claims
  std::string jwt_payload;
  Protobuf::util::MessageToJsonString(claim_structs, &jwt_payload);
  setKeyValue(authn_data, istio::utils::AttributeName::kRequestAuthRawClaims,
              jwt_payload);
  return true;
}

void AuthnV2Filter::onDestroy() {
  ENVOY_LOG(debug, "Called AuthnV2Filter : {}", __func__);
}

std::pair<std::string, const ProtobufWkt::Struct*>
AuthnV2Filter::extractJwtFromMetadata(
    const envoy::api::v2::core::Metadata& metadata, std::string* jwt_payload) {
  auto result = std::pair<std::string, const ProtobufWkt::Struct*>("", nullptr);
  std::string issuer_selected = "";
  auto filter_it = metadata.filter_metadata().find(
      Extensions::HttpFilters::HttpFilterNames::get().JwtAuthn);
  if (filter_it == metadata.filter_metadata().end()) {
    return result;
  }
  const ProtobufWkt::Struct& jwt_metadata = filter_it->second;
  // Iterate over the envoy.jwt metadata, which is indexed by the issuer.
  // For multiple JWT, we only select on of them, the first one lexically
  // sorted.
  for (const auto& entry : jwt_metadata.fields()) {
    const std::string& issuer = entry.first;
    if (issuer_selected == "" || issuer_selected.compare(issuer) > 0) {
      issuer_selected = issuer;
    }
  }
  if (issuer_selected != "") {
    const auto& jwt_entry = jwt_metadata.fields().find(issuer_selected);
    result.first = issuer_selected;
    result.second = &(jwt_entry->second.struct_value());
    Protobuf::util::MessageToJsonString(jwt_entry->second.struct_value(),
                                        jwt_payload);
  }
  return result;
}

FilterHeadersStatus AuthnV2Filter::decodeHeaders(HeaderMap&, bool) {
  auto& metadata = decoder_callbacks_->streamInfo().dynamicMetadata();
  auto& authn_data =
      (*metadata.mutable_filter_metadata())[Utils::IstioFilterName::kAuthnV2];

  // Always try to get principal and set to output if available.
  if (!ProcessMtls(decoder_callbacks_->connection(), authn_data)) {
    ENVOY_LOG(warn, "unable to extract peer identity");
  }
  std::string jwt_payload = "";
  auto result = extractJwtFromMetadata(metadata, &jwt_payload);
  ENVOY_LOG(debug,
            "extract jwt metadata {} \njwt payload issuer {}, payload\n{}\n",
            metadata.DebugString(), result.first, jwt_payload);
  if (result.first != "") {
    processJwt(*result.second, authn_data);
  }
  ENVOY_LOG(debug, "saved dynamic metadata:\n{}",
            Envoy::MessageUtil::getYamlStringFromMessage(
                decoder_callbacks_->streamInfo()
                    .dynamicMetadata()
                    .filter_metadata()
                    .at(Utils::IstioFilterName::kAuthnV2),
                true, true));
  return FilterHeadersStatus::Continue;
}

}  // namespace AuthN
}  // namespace Istio
}  // namespace Http
}  // namespace Envoy
