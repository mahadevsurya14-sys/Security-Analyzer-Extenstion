/**
 * Security Analyzer - Background Service Worker (Manifest V3)
 * Collects HTTP response headers, manages tab state, and provides
 * background orchestration for technology & security audits.
 */

// Memory cache for observed main_frame headers
const tabHeaderCache = new Map();

// Load fingerprints JSON database
let fingerprintsCache = null;

async function loadFingerprints() {
  if (fingerprintsCache) return fingerprintsCache;
  try {
    const url = chrome.runtime.getURL('engine/fingerprints.json');
    const res = await fetch(url);
    fingerprintsCache = await res.json();
    return fingerprintsCache;
  } catch (e) {
    console.error('Failed to load fingerprints.json', e);
    return { technologies: [] };
  }
}

// Intercept main_frame headers via webRequest API
if (chrome.webRequest && chrome.webRequest.onHeadersReceived) {
  try {
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        if (details.type === 'main_frame' && details.responseHeaders) {
          const headerMap = {};
          for (const h of details.responseHeaders) {
            headerMap[h.name.toLowerCase()] = h.value;
          }
          tabHeaderCache.set(details.tabId, {
            url: details.url,
            headers: headerMap,
            statusCode: details.statusCode,
            timestamp: Date.now()
          });
        }
      },
      { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
      ['responseHeaders']
    );
  } catch (e) {
    console.warn('webRequest listener registration notice:', e);
  }
}

// Clean up cache when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  tabHeaderCache.delete(tabId);
});

/**
 * Passive header collector fallback using HEAD request
 */
async function fetchHeadersPassively(url) {
  try {
    const resp = await fetch(url, {
      method: 'HEAD',
      credentials: 'omit',
      cache: 'no-store',
      signal: AbortSignal.timeout(2000)
    });
    const headers = {};
    resp.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });
    return { success: true, headers, status: resp.status };
  } catch (e) {
    // Some servers reject HEAD; try GET with range header
    try {
      const resp2 = await fetch(url, {
        method: 'GET',
        headers: { Range: 'bytes=0-10' },
        credentials: 'omit',
        cache: 'no-store',
        signal: AbortSignal.timeout(2000)
      });
      const headers = {};
      resp2.headers.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
      return { success: true, headers, status: resp2.status };
    } catch (e2) {
      return { success: false, error: e2.message, headers: {} };
    }
  }
}

// Message Dispatcher
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || !request.action) return false;

  switch (request.action) {
    case 'GET_CACHED_HEADERS': {
      const tabId = request.tabId;
      const cached = tabHeaderCache.get(tabId);
      if (cached) {
        sendResponse({ success: true, data: cached });
      } else {
        // Fallback fetch
        if (request.url) {
          fetchHeadersPassively(request.url).then(res => {
            if (res.success) {
              tabHeaderCache.set(tabId, {
                url: request.url,
                headers: res.headers,
                statusCode: res.status,
                timestamp: Date.now()
              });
            }
            sendResponse({ success: res.success, data: { headers: res.headers, url: request.url } });
          });
          return true;
        }
        sendResponse({ success: false, data: { headers: {} } });
      }
      return true;
    }

    case 'FETCH_PASSIVE_HEADERS': {
      fetchHeadersPassively(request.url).then(res => sendResponse(res));
      return true;
    }

    case 'GET_FINGERPRINTS': {
      loadFingerprints().then(fp => sendResponse({ success: true, fingerprints: fp }));
      return true;
    }

    case 'CHECK_BACKEND_STATUS': {
      const backendUrl = request.backendUrl || 'http://127.0.0.1:8000';
      fetch(`${backendUrl}/api/health`, { method: 'GET', signal: AbortSignal.timeout(2000) })
        .then(res => res.json())
        .then(data => sendResponse({ available: true, data }))
        .catch(() => sendResponse({ available: false }));
      return true;
    }

    default:
      sendResponse({ error: 'Unknown action' });
      return false;
  }
});
