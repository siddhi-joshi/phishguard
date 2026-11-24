// Marks each tab's toolbar icon with a badge when the address looks risky.
importScripts('analyzer.js');

const BADGES = {
  dangerous: { text: '!', color: '#C62F2F' },
  suspicious: { text: '?', color: '#C77700' }
};

function updateBadge(tabId, url) {
  if (!url) return;
  const { verdict } = PhishCheck.analyze(url);
  const badge = BADGES[verdict];
  chrome.action.setBadgeText({ tabId, text: badge ? badge.text : '' });
  if (badge) chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'complete') updateBadge(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, tab => { if (!chrome.runtime.lastError) updateBadge(tabId, tab.url); });
});
