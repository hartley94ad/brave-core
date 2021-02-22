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
#include "brave/browser/ipfs/ipfs_dns_resolver.h"
#include "brave/browser/ipfs/ipfs_service_factory.h"
#include "brave/components/ipfs/ipfs_constants.h"
#include "brave/components/ipfs/ipfs_utils.h"
#include "brave/components/ipfs/pref_names.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "chrome/browser/shell_integration.h"
#include "components/prefs/pref_service.h"
#include "components/user_prefs/user_prefs.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/storage_partition.h"
#include "brave/components/ipfs/ipfs_utils.h"
#include "chrome/common/channel_info.h"


namespace {
const char kDnsLinkHeader[] = "dnslink";
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

// Expects dns TXT record in format: name=value
std::string GetDSNRecordValue(const std::vector<std::string>& text_results,
                              const std::string& name) {
  for (const auto& txt: text_results) {
    if (!base::StartsWith(txt, name))
      continue;
    std::vector<std::string> tokens = base::SplitString(
      txt, "=", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    if (!tokens.size())
      continue;
    return tokens.back();
  }
  return std::string();
}
}  // namespace

namespace ipfs {

IPFSTabHelper::~IPFSTabHelper() = default;

IPFSTabHelper::IPFSTabHelper(content::WebContents* web_contents)
    : content::WebContentsObserver(web_contents),
      resolver_(new IPFSDNSResolver()) {
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

void IPFSTabHelper::DNSResolvedCallback(const std::string& host, 
  const std::vector<std::string>& text_results) {
  
  std::string dnslink = GetDSNRecordValue(text_results, kDnsLinkHeader);
  if (dnslink.empty())
    return;
    
  DLOG(INFO) << "dnslink for " << host << " resolved as " << dnslink;
  std::vector<std::string> tokens = base::SplitString(
      dnslink, "ipfs/", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  base::ReplaceFirstSubstringAfterOffset(&dnslink, 0, "/ipfs/", "ipfs://");

  ipfs_url_ = GURL(dnslink);
  /*GURL raw_url(web_contents()->GetURL());
  GURL::Replacements replacements;
  replacements.SetPathStr(dnslink);

  if (!::ipfs::ResolveIPFSURI(
            web_contents()->GetBrowserContext(),
            chrome::GetChannel(),
            raw_url.ReplaceComponents(replacements),
            &ipfs_url_)) {
  }*/
}

void IPFSTabHelper::ResolveIPFSLink() {
  if (resolver_->IsRunning()) {
    if (resolver_->host() == web_contents()->GetURL().host())
        return;
    resolver_->Stop();
  }

  auto* storage_partition = content::BrowserContext::GetDefaultStoragePartition(
      web_contents()->GetBrowserContext());
  auto resolved_callback =
      base::BindOnce(&IPFSTabHelper::DNSResolvedCallback,
                     weak_ptr_factory_.GetWeakPtr());
  resolver_->Resolve(net::HostPortPair::FromURL(web_contents()->GetURL()),
                      web_contents()->GetMainFrame()->GetNetworkIsolationKey(),
                      storage_partition->GetNetworkContext(),
                      net::DnsQueryType::TXT, std::move(resolved_callback));
}

void IPFSTabHelper::DidFinishNavigation(content::NavigationHandle* handle) {
  DCHECK(handle);
  if (!handle->IsInMainFrame()) {
    return;
  }
  ipfs_url_ = GURL();
  auto resolve_method = static_cast<ipfs::IPFSResolveMethodTypes>(
      pref_service_->GetInteger(kIPFSResolveMethod));
  auto* browser_context = web_contents()->GetBrowserContext();
  if (handle->GetResponseHeaders() &&
      handle->GetResponseHeaders()->HasHeader("x-ipfs-path")) {
    ResolveIPFSLink();
  }
  if (resolve_method == ipfs::IPFSResolveMethodTypes::IPFS_ASK &&
      handle->GetResponseHeaders() &&
      handle->GetResponseHeaders()->HasHeader("x-ipfs-path") &&
      IsDefaultGatewayURL(GURL(handle->GetURL()), browser_context)) {
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
