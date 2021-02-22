/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_BROWSER_IPFS_IPFS_DNS_RESOLVER_H_
#define BRAVE_BROWSER_IPFS_IPFS_DNS_RESOLVER_H_

#include <string>

#include "net/base/network_isolation_key.h"
#include "services/network/network_context.h"
#include "services/network/public/cpp/resolve_host_client_base.h"
#include "services/network/public/mojom/host_resolver.mojom.h"

namespace ipfs {

class IPFSDNSResolver final : public network::ResolveHostClientBase {
 public:
  IPFSDNSResolver();
  ~IPFSDNSResolver() override;

  using DNSTextResultsCallback =
    base::OnceCallback<void(const std::string& host,
                            const std::vector<std::string>& text_results)>;

  void Resolve(const net::HostPortPair& host,
              const net::NetworkIsolationKey& isolation_key,
              network::mojom::NetworkContext* network_context,
              net::DnsQueryType dns_query_type,
              DNSTextResultsCallback callback);
  
  bool IsRunning() const;
  void Stop();
  
  std::string host() const {
    return resolving_host_;
  }

private:
  // network::mojom::ResolveHostClient implementation:
  void OnComplete(
      int result,
      const net::ResolveErrorInfo& resolve_error_info,
      const base::Optional<net::AddressList>& resolved_addresses) override;
  void OnTextResults(const std::vector<std::string>& text_results) override;


  std::string resolving_host_;
  mojo::Remote<network::mojom::HostResolver> host_resolver_;
  DNSTextResultsCallback callback_;
  mojo::Receiver<network::mojom::ResolveHostClient> receiver_{this};
};

}  // namespace ipfs

#endif  // BRAVE_BROWSER_IPFS_IPFS_DNS_RESOLVER_H_
