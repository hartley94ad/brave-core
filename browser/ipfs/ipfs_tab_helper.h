/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_BROWSER_IPFS_IPFS_TAB_HELPER_H_
#define BRAVE_BROWSER_IPFS_IPFS_TAB_HELPER_H_

#include <memory>

#include "content/public/browser/web_contents_observer.h"
#include "content/public/browser/web_contents_user_data.h"


namespace content {
class NavigationHandle;
class WebContents;
}  // namespace content

class PrefService;

namespace ipfs {

class IPFSDNSResolver;

// Determines if IPFS should be active for a given top-level navigation.
class IPFSTabHelper : public content::WebContentsObserver,
                      public content::WebContentsUserData<IPFSTabHelper> {
 public:
  ~IPFSTabHelper() override;

  IPFSTabHelper(const IPFSTabHelper&) = delete;
  IPFSTabHelper& operator=(IPFSTabHelper&) = delete;

  static bool MaybeCreateForWebContents(content::WebContents* web_contents);
  GURL ipfs_url() const {
    return ipfs_url_;
  }

 private:
  friend class content::WebContentsUserData<IPFSTabHelper>;
  explicit IPFSTabHelper(content::WebContents* web_contents);

  // content::WebContentsObserver
  void DidFinishNavigation(
      content::NavigationHandle* navigation_handle) override;
  void ResolveIPFSLink();
  void DNSResolvedCallback(const std::string& host,
                           const std::vector<std::string>& text_results);

  PrefService* pref_service_ = nullptr;
  GURL ipfs_url_;
  std::unique_ptr<IPFSDNSResolver> resolver_;
  base::WeakPtrFactory<IPFSTabHelper> weak_ptr_factory_{this};
  WEB_CONTENTS_USER_DATA_KEY_DECL();
};

}  // namespace ipfs

#endif  // BRAVE_BROWSER_IPFS_IPFS_TAB_HELPER_H_
