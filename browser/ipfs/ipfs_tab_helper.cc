/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/browser/ipfs/ipfs_tab_helper.h"

#include <string>
#include <vector>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/containers/contains.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "net/base/completion_repeating_callback.h"
#include "brave/browser/ipfs/ipfs_service_factory.h"
#include "brave/components/ipfs/ipfs_constants.h"
#include "brave/components/ipfs/ipfs_utils.h"
#include "brave/components/ipfs/pref_names.h"
#include "chrome/browser/shell_integration.h"
#include "components/prefs/pref_service.h"
#include "components/user_prefs/user_prefs.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/navigation_handle.h"
#include "services/network/public/cpp/resolve_host_client_base.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/host_resolver.mojom.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "net/base/completion_repeating_callback.h"
#include "net/base/net_errors.h"
#include "chrome/browser/browser_process_impl.h"
#include "net/base/network_isolation_key.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/tcp_client_socket.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/browser/render_frame_host.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/cpp/resolve_host_client_base.h"
#include "services/network/public/mojom/host_resolver.mojom.h"
#include "net/dns/public/dns_protocol.h"
#include "base/strings/string_split.h"

namespace {
const uint8_t kGooglePublicDns1[] = {8, 8, 8, 8};
const uint8_t kGooglePublicDns2[] = {8, 8, 4, 4};
// Sets current executable as default protocol handler in a system.
void SetupIPFSProtocolHandler(const std::string& protocol) {
  auto isDefaultCallback = [](const std::string& protocol,
                              shell_integration::DefaultWebClientState state) {
    if (state == shell_integration::IS_DEFAULT) {
      VLOG(1) << protocol << " already has a handler";
      return;
    }
    VLOG(1) << "Set as default handler for " << protocol;
    // The worker pointer is reference counted. While it is running, the
    // sequence it runs on will hold references it will be automatically
    // freed once all its tasks have finished.
    base::MakeRefCounted<shell_integration::DefaultProtocolClientWorker>(
        protocol)
        ->StartSetAsDefault(base::NullCallback());
  };

  base::MakeRefCounted<shell_integration::DefaultProtocolClientWorker>(protocol)
      ->StartCheckIsDefault(base::BindOnce(isDefaultCallback, protocol));
}

using ResolvedCallback = base::OnceCallback<void()>;


class DSNink final : public network::ResolveHostClientBase {
 public:
  ResolveHostAndOpenSocket(content::WebContents* content, const GURL& url,
                          net::DnsConfigOverrides dns_overrides,
                           ResolvedCallback callback)
      : callback_(std::move(callback)) {

    //auto* render_frame_host = content->GetMainFrame();

  //std::unique_ptr<net::ContextHostResolver> inner_resolver =
  //    net::HostResolver::CreateStandaloneContextResolver(net::NetLog::Get());

    //url::Origin origin = url::Origin::Create(url);
    DLOG(INFO) << "url:" << url;
    network::mojom::NetworkContext* network_context =
    //    content::BrowserContext::GetDefaultStoragePartition(content->GetBrowserContext())
      g_browser_process->system_network_context_manager()->GetContext();
            //->GetNetworkContext();
    host_resolver_.reset();
    network_context->CreateHostResolver(
      dns_overrides, host_resolver_.BindNewPipeAndPassReceiver());

    network::mojom::ResolveHostParametersPtr optional_parameters =
      network::mojom::ResolveHostParameters::New();
    optional_parameters->dns_query_type = net::DnsQueryType::TXT;
    optional_parameters->source = net::HostResolverSource::DNS;
    optional_parameters->cache_usage =
      network::mojom::ResolveHostParameters::CacheUsage::DISALLOWED;
    optional_parameters->include_canonical_name = true;

    host_resolver_->ResolveHost(
                          net::HostPortPair::FromURL(url),
                          net::NetworkIsolationKey(),
                          std::move(optional_parameters),
                          receiver_.BindNewPipeAndPassRemote());
    receiver_.set_disconnect_handler(
        base::BindOnce(&ResolveHostAndOpenSocket::OnComplete,
                       base::Unretained(this), net::ERR_NAME_NOT_RESOLVED,
                       net::ResolveErrorInfo(net::ERR_FAILED), base::nullopt));
  }

 private:
  // network::mojom::ResolveHostClient implementation:
  void OnComplete(
      int result,
      const net::ResolveErrorInfo& resolve_error_info,
      const base::Optional<net::AddressList>& resolved_addresses) override {
    DLOG(INFO) << "ErrorToString:" << net::ErrorToString(result);
    if (result != net::OK) {
      
      if (callback_)
        std::move(callback_).Run();
     // delete this;
      return;
    }
    return;
    //delete this;
  }

  void OnTextResults(const std::vector<std::string>& text_results) override {
    if (!text_results.size())
      return;

    for (const auto& txt: text_results) {
      std::vector<std::string> tokens = base::SplitString(
        txt, "=", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
      if (!tokens.size())
        continue;
      if (tokens.front() != "dnslink")
        continue;
      std::string link = tokens.back();
      DLOG(INFO) << "ipfs:" << link;
    }
    DLOG(INFO) << "TEXT:" << text_results.front();
  }
  void OnHostnameResults(const std::vector<net::HostPortPair>& hosts) override {
      DLOG(INFO) << "HOST";
  }
  mojo::Remote<network::mojom::HostResolver> host_resolver_;
  ResolvedCallback callback_;
  mojo::Receiver<network::mojom::ResolveHostClient> receiver_{this};
};

}  // namespace

namespace ipfs {

IPFSTabHelper::~IPFSTabHelper() = default;

IPFSTabHelper::IPFSTabHelper(content::WebContents* web_contents)
    : content::WebContentsObserver(web_contents) {
  pref_service_ = user_prefs::UserPrefs::Get(web_contents->GetBrowserContext());
}

// static
bool IPFSTabHelper::MaybeCreateForWebContents(
    content::WebContents* web_contents) {
  if (!ipfs::IpfsServiceFactory::GetForContext(
          web_contents->GetBrowserContext())) {
    return false;
  }

  CreateForWebContents(web_contents);
  return true;
}

void IPFSTabHelper::ResolvedCallback() {

}

void IPFSTabHelper::DidFinishNavigation(content::NavigationHandle* handle) {
  DCHECK(handle);
  if (!handle->IsInMainFrame()) {
    return;
  }

  auto resolve_method = static_cast<ipfs::IPFSResolveMethodTypes>(
      pref_service_->GetInteger(kIPFSResolveMethod));
  auto* browser_context = web_contents()->GetBrowserContext();
  if (handle->GetResponseHeaders() &&
      handle->GetResponseHeaders()->HasHeader("x-ipfs-path")) {
      if (!called_) {
        count_++;
        called_ = true;
        net::DnsConfigOverrides overrides = net::DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
        overrides.nameservers = std::vector<net::IPEndPoint>{
            net::IPEndPoint(net::IPAddress(kGooglePublicDns1),
                            net::dns_protocol::kDefaultPort),
            net::IPEndPoint(net::IPAddress(kGooglePublicDns2),
                            net::dns_protocol::kDefaultPort)};
        overrides.attempts = 1;
        overrides.secure_dns_mode = net::SecureDnsMode::kOff;
        DLOG(INFO) << "count:" << count_;
        new ResolveHostAndOpenSocket(web_contents(), handle->GetURL(), overrides, 
                  base::BindOnce(&IPFSTabHelper::ResolvedCallback,
                    weak_ptr_factory_.GetWeakPtr()));
    }
  }
  if (resolve_method == ipfs::IPFSResolveMethodTypes::IPFS_ASK &&
      handle->GetResponseHeaders() &&
      handle->GetResponseHeaders()->HasHeader("x-ipfs-path") &&
      IsDefaultGatewayURL(GURL("ns1.ethdns.xyz"), browser_context)) {
    auto infobar_count = pref_service_->GetInteger(kIPFSInfobarCount);
    if (!infobar_count) {
      pref_service_->SetInteger(kIPFSInfobarCount, infobar_count + 1);
      SetupIPFSProtocolHandler(ipfs::kIPFSScheme);
      SetupIPFSProtocolHandler(ipfs::kIPNSScheme);
    }
  }
}

WEB_CONTENTS_USER_DATA_KEY_IMPL(IPFSTabHelper)

}  // namespace ipfs
