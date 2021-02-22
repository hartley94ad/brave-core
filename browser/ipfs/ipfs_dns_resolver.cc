/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/browser/ipfs/ipfs_dns_resolver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "net/base/host_port_pair.h"
#include "net/dns/public/dns_protocol.h"
#include "services/network/network_context.h"

namespace {
  
const uint8_t kGooglePublicDns1[] = {8, 8, 8, 8};
const uint8_t kGooglePublicDns2[] = {8, 8, 4, 4};

}

namespace ipfs {

IPFSDNSResolver::IPFSDNSResolver() {}
IPFSDNSResolver::~IPFSDNSResolver() {}

void IPFSDNSResolver::Resolve(const net::HostPortPair& host,
           const net::NetworkIsolationKey& isolation_key,
           network::mojom::NetworkContext* network_context,
           net::DnsQueryType dns_query_type,
           DNSTextResultsCallback callback) {
  if (IsRunning())
    Stop();
  net::DnsConfigOverrides overrides =
    net::DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
  overrides.nameservers = std::vector<net::IPEndPoint>{
      net::IPEndPoint(net::IPAddress(kGooglePublicDns1),
                      net::dns_protocol::kDefaultPort),
      net::IPEndPoint(net::IPAddress(kGooglePublicDns2),
                      net::dns_protocol::kDefaultPort)};
  overrides.attempts = 1;

  network_context->CreateHostResolver(
    overrides, host_resolver_.BindNewPipeAndPassReceiver());
  
  network::mojom::ResolveHostParametersPtr optional_parameters =
    network::mojom::ResolveHostParameters::New();
  optional_parameters->dns_query_type = dns_query_type;
  optional_parameters->source = net::HostResolverSource::DNS;
  optional_parameters->cache_usage =
    network::mojom::ResolveHostParameters::CacheUsage::DISALLOWED;
  optional_parameters->include_canonical_name = true;
  resolving_host_ = host.host();
  callback_ = std::move(callback);
  host_resolver_->ResolveHost(host,
                              isolation_key,
                              std::move(optional_parameters),
                              receiver_.BindNewPipeAndPassRemote());
  receiver_.set_disconnect_handler(
      base::BindOnce(&IPFSDNSResolver::OnComplete,
                      base::Unretained(this), net::ERR_NAME_NOT_RESOLVED,
                      net::ResolveErrorInfo(net::ERR_FAILED), base::nullopt));
}

bool IPFSDNSResolver::IsRunning() const {
  return !resolving_host_.empty();
}

void IPFSDNSResolver::Stop() {
  if (host_resolver_.is_bound()) {
    host_resolver_.reset();
  }
  resolving_host_.erase();
}

void IPFSDNSResolver::OnComplete(int result,
                                 const net::ResolveErrorInfo& error_info,
                                 const base::Optional<net::AddressList>& list) {
  if (result != net::OK)
    VLOG(1) << "DNS resolving error:" << net::ErrorToString(result);
  Stop();
}

void IPFSDNSResolver::OnTextResults(const std::vector<std::string>& results) {
  if (callback_)
    std::move(callback_).Run(resolving_host_, results);
  Stop();
}

}  // namespace
