/**
 * Security Analyzer - Content Script
 * Gathers DOM metadata, scripts, stylesheets, resource timing entries,
 * CSS indicators, and coordinates with page-script.js for runtime globals.
 */

(function () {
  'use strict';

  let discoveredGlobals = {};

  // Listen for globals broadcasted by page-script.js
  window.addEventListener('SECURITY_ANALYZER_GLOBALS_DISCOVERED', function (e) {
    if (e.detail && typeof e.detail === 'object') {
      discoveredGlobals = Object.assign({}, discoveredGlobals, e.detail);
    }
  });

  // Inject page-script into page DOM to execute in MAIN world
  function injectPageScript() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('content/page-script.js');
      script.onload = function () {
        this.remove();
      };
      (document.head || document.documentElement).appendChild(script);
    } catch (e) {
      // Fallback
    }
  }

  // Trigger injection
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectPageScript);
  } else {
    injectPageScript();
  }

  /**
   * Scrapes DOM artifacts and resource timings
   */
  function gatherPageData() {
    // 1. Meta tags
    const meta = {};
    const metaTags = document.querySelectorAll('meta');
    for (const tag of metaTags) {
      const name = tag.getAttribute('name') || tag.getAttribute('property') || tag.getAttribute('http-equiv');
      const content = tag.getAttribute('content');
      if (name && content) {
        meta[name.toLowerCase()] = content;
      }
    }

    // 2. Script source URLs
    const scripts = [];
    const scriptTags = document.querySelectorAll('script[src]');
    for (const s of scriptTags) {
      const src = s.getAttribute('src');
      if (src) {
        try {
          scripts.push(new URL(src, window.location.href).href);
        } catch (e) {
          scripts.push(src);
        }
      }
    }

    // 3. Link tags
    const links = [];
    const linkTags = document.querySelectorAll('link[href]');
    for (const l of linkTags) {
      const href = l.getAttribute('href');
      if (href) {
        try {
          links.push(new URL(href, window.location.href).href);
        } catch (e) {
          links.push(href);
        }
      }
    }

    // 4. Resource Timing Entries (Catches dynamically injected scripts, CDNs, analytics)
    const resources = [];
    try {
      if (window.performance && typeof window.performance.getEntriesByType === 'function') {
        const entries = window.performance.getEntriesByType('resource');
        for (let i = 0; i < Math.min(entries.length, 120); i++) {
          if (entries[i].name) {
            resources.push(entries[i].name);
          }
        }
      }
    } catch (e) {}

    // Combine static script tags and dynamically loaded resource scripts
    const combinedScriptUrls = Array.from(new Set([
      ...scripts,
      ...resources.filter(r => r.endsWith('.js') || r.includes('.js?') || r.includes('/js/') || r.includes('script'))
    ]));

    // 5. Selectors test
    const testSelectors = [
      '[data-reactroot]',
      '[data-reactid]',
      '#___gatsby',
      '#wpadminbar',
      '[ng-version]',
      '[_nghost-[a-z0-9]+]',
      '[data-v-[a-z0-9]+]',
      '#__nuxt',
      'script#__NEXT_DATA__',
      '[x-data]',
      '[x-init]',
      '[class*="svelte-"]',
      'link[rel*="https://api.w.org/"]',
      'script[data-drupal-selector]',
      '.ghost-portal-root',
      '[data-bs-toggle]',
      '[data-bs-target]',
      '#django-admin-prepopulated-fields-constants',
      'astro-island',
      '[data-wf-site]',
      '.cf-turnstile',
      '.g-recaptcha',
      '.h-captcha',
      'link[rel="manifest"]'
    ];

    const matchedSelectors = [];
    for (const sel of testSelectors) {
      try {
        if (document.querySelector(sel)) {
          matchedSelectors.push(sel);
        }
      } catch (e) {}
    }

    // Check specific ng-version attribute value
    const ngEl = document.querySelector('[ng-version]');
    if (ngEl) {
      discoveredGlobals['angular.version.full'] = ngEl.getAttribute('ng-version');
    }

    // 6. CSS Framework Class Signature Inspection
    const cssSignatures = [];
    try {
      if (document.querySelector('[class*="tw-"], [class*="max-w-"], [class*="min-h-"]')) {
        cssSignatures.push('tailwind');
      }
      if (document.querySelector('.container-fluid, .row, .col-md-, .btn-primary')) {
        cssSignatures.push('bootstrap');
      }
      if (document.querySelector('[class*="MuiButton-"], [class*="MuiBox-"], [class*="MuiTypography-"]')) {
        cssSignatures.push('material-ui');
      }
      if (document.querySelector('[class*="chakra-"]')) {
        cssSignatures.push('chakra-ui');
      }
      if (document.querySelector('[class*="ant-"]')) {
        cssSignatures.push('ant-design');
      }
      if (document.querySelector('.is-primary, .navbar-item, .has-text-centered')) {
        cssSignatures.push('bulma');
      }
      if (document.querySelector('.fa, .fas, .fab, .far, [class*="fa-"]')) {
        cssSignatures.push('font-awesome');
      }
    } catch (e) {}

    // 7. PWA Status
    const pwa = {
      hasManifest: !!document.querySelector('link[rel="manifest"]'),
      hasServiceWorker: !!(navigator.serviceWorker && navigator.serviceWorker.controller),
      themeColor: meta['theme-color'] || null,
      hasAppleTouchIcon: !!document.querySelector('link[rel="apple-touch-icon"]')
    };

    // 8. Safe cookie names only (no values for privacy)
    const cookieNames = [];
    try {
      const cookies = document.cookie ? document.cookie.split(';') : [];
      for (const c of cookies) {
        const parts = c.trim().split('=');
        if (parts[0]) {
          cookieNames.push(parts[0]);
        }
      }
    } catch (e) {}

    // 9. Truncated HTML for string signatures (max 40KB)
    let htmlSnippet = '';
    try {
      htmlSnippet = (document.documentElement ? document.documentElement.outerHTML : '').slice(0, 40000);
    } catch (e) {}

    return {
      url: window.location.href,
      title: document.title,
      meta,
      scripts: combinedScriptUrls,
      links,
      resources,
      selectors: matchedSelectors,
      cssSignatures,
      pwa,
      cookies: cookieNames,
      html: htmlSnippet,
      globals: discoveredGlobals
    };
  }

  // Listen for message from extension popup or background
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request && request.action === 'COLLECT_PAGE_DATA') {
      window.dispatchEvent(new CustomEvent('SECURITY_ANALYZER_PROBE_GLOBALS_REQUEST'));
      setTimeout(() => {
        const data = gatherPageData();
        sendResponse({ success: true, pageData: data });
      }, 50);
      return true;
    }
  });

})();
