// MV3 Service Worker (background)
// Helps open background tabs upon request.

chrome.runtime.onMessage.addListener((msg, _sender, _sendResponse) => {
  if (msg?.type === 'PG_OPEN_BG_TAB' && msg.url) {
    chrome.tabs.create({ url: msg.url, active: false });
  }
});
