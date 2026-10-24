/**
 * Security Analyzer - Popup Application Controller
 * Handles UI state, tab navigation, active tab audits, filtering,
 * deep scans, and report exports.
 */

document.addEventListener('DOMContentLoaded', async () => {
  'use strict';

  // Application State
  const state = {
    activeTab: null,
    targetUrl: '',
    pageData: null,
    headers: {},
    fingerprints: null,
    detectedTechnologies: [],
    securityAudit: null,
    vulnerabilities: null,
    deepScanResults: null,
    deepScanner: null,
    settings: {
      backendUrl: 'http://127.0.0.1:8000',
      useBackend: false,
      autoScan: true,
      deepTimeout: 10
    }
  };

  // DOM Elements
  const els = {
    targetUrlText: document.getElementById('targetUrlText'),
    scanTimestamp: document.getElementById('scanTimestamp'),
    headerScoreBadge: document.getElementById('headerScoreBadge'),
    rescanBtn: document.getElementById('rescanBtn'),
    loadingState: document.getElementById('loadingState'),
    loadingMsg: document.getElementById('loadingMsg'),
    errorState: document.getElementById('errorState'),
    errorMsg: document.getElementById('errorMsg'),
    retryBtn: document.getElementById('retryBtn'),
    openDemoBtn: document.getElementById('openDemoBtn'),
    
    // Badges & Counters
    techBadge: document.getElementById('techBadge'),
    secBadge: document.getElementById('secBadge'),
    vulnBadge: document.getElementById('vulnBadge'),
    cntTechs: document.getElementById('cntTechs'),
    cntLanguages: document.getElementById('cntLanguages'),
    cntFindings: document.getElementById('cntFindings'),
    cntVulns: document.getElementById('cntVulns'),
    overviewScoreNum: document.getElementById('overviewScoreNum'),
    overviewGradeText: document.getElementById('overviewGradeText'),
    overviewRatingDesc: document.getElementById('overviewRatingDesc'),
    overviewStackList: document.getElementById('overviewStackList'),
    overviewLanguageList: document.getElementById('overviewLanguageList'),
    langBannerBadges: document.getElementById('langBannerBadges'),

    // Severity Counters
    sevCntCritical: document.getElementById('sevCntCritical'),
    sevCntHigh: document.getElementById('sevCntHigh'),
    sevCntMedium: document.getElementById('sevCntMedium'),
    sevCntLow: document.getElementById('sevCntLow'),
    sevCntInfo: document.getElementById('sevCntInfo'),

    // Containers
    techsListContainer: document.getElementById('techsListContainer'),
    versionsListContainer: document.getElementById('versionsListContainer'),
    securityListContainer: document.getElementById('securityListContainer'),
    vulnListContainer: document.getElementById('vulnListContainer'),
    deepScanResultsContainer: document.getElementById('deepScanResultsContainer'),

    // Filters
    techSearchInput: document.getElementById('techSearchInput'),
    techCategoryFilter: document.getElementById('techCategoryFilter'),
    secSearchInput: document.getElementById('secSearchInput'),
    secSeverityFilter: document.getElementById('secSeverityFilter'),

    // Deep Scan
    startDeepScanBtn: document.getElementById('startDeepScanBtn'),
    cancelDeepScanBtn: document.getElementById('cancelDeepScanBtn'),
    deepScanProgressBox: document.getElementById('deepScanProgressBox'),
    deepProgressBar: document.getElementById('deepProgressBar'),
    deepProgressStatus: document.getElementById('deepProgressStatus'),

    // Export
    exportJsonBtn: document.getElementById('exportJsonBtn'),
    exportCsvBtn: document.getElementById('exportCsvBtn'),

    // Settings
    settingBackendUrl: document.getElementById('settingBackendUrl'),
    settingUseBackend: document.getElementById('settingUseBackend'),
    settingAutoScan: document.getElementById('settingAutoScan'),
    settingDeepTimeout: document.getElementById('settingDeepTimeout'),
    saveSettingsBtn: document.getElementById('saveSettingsBtn'),
    saveNotice: document.getElementById('saveNotice'),
    backendStatusPill: document.getElementById('backendStatusPill')
  };

  // 1. Navigation Tab Switching
  document.querySelectorAll('.nav-tab').forEach(tabBtn => {
    tabBtn.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tabBtn.classList.add('active');
      const targetId = tabBtn.getAttribute('data-tab');
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  // 2. Load Settings & Check Backend
  await loadSettings();

  // 3. Setup Deep Scanner
  if (window.SecurityAnalyzerDeepScanner) {
    state.deepScanner = new window.SecurityAnalyzerDeepScanner.DeepScanner();
  }

  // 4. Bind Action Listeners
  els.rescanBtn.addEventListener('click', () => runAudit(true));
  els.retryBtn.addEventListener('click', () => runAudit(true));
  if (els.openDemoBtn) {
    els.openDemoBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'https://wordpress.org' });
      window.close();
    });
  }

  els.techSearchInput.addEventListener('input', renderTechnologies);
  els.techCategoryFilter.addEventListener('change', renderTechnologies);
  els.secSearchInput.addEventListener('input', renderSecurityFindings);
  els.secSeverityFilter.addEventListener('change', renderSecurityFindings);

  els.startDeepScanBtn.addEventListener('click', startDeepScan);
  els.cancelDeepScanBtn.addEventListener('click', cancelDeepScan);

  els.exportJsonBtn.addEventListener('click', exportJsonReport);
  els.exportCsvBtn.addEventListener('click', exportCsvReport);

  els.saveSettingsBtn.addEventListener('click', saveSettings);

  // 5. Initial Audit Trigger
  runAudit();

  /**
   * Main audit controller
   */
  async function runAudit(force = false) {
    hideError();
    showLoading('Identifying target tab and collecting security indicators...');

    try {
      // Query active tab across all windows
      let tab = null;
      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs.length > 0) tab = tabs[0];
      } catch (e) {}

      if (!tab) {
        try {
          const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
          if (tabs && tabs.length > 0) tab = tabs[0];
        } catch (e) {}
      }

      if (!tab) {
        try {
          const tabs = await chrome.tabs.query({ active: true });
          if (tabs && tabs.length > 0) tab = tabs[0];
        } catch (e) {}
      }

      if (!tab || !tab.url) {
        showError('No active browser tab found. Please open a webpage and try again.');
        return;
      }

      state.activeTab = tab;
      state.targetUrl = tab.url;
      els.targetUrlText.textContent = tab.url;
      els.targetUrlText.title = tab.url;

      // Validate URL scheme
      if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
        showError('Cannot analyze restricted browser pages (e.g. chrome:// or edge://). Click the button below to open a live website.');
        return;
      }

      // Load fingerprints database directly
      if (!state.fingerprints) {
        try {
          const localRes = await fetch(chrome.runtime.getURL('engine/fingerprints.json'));
          state.fingerprints = await localRes.json();
        } catch (e) {
          const fpRes = await chrome.runtime.sendMessage({ action: 'GET_FINGERPRINTS' });
          if (fpRes && fpRes.fingerprints) {
            state.fingerprints = fpRes.fingerprints;
          }
        }
      }

      showLoading('Collecting HTTP response headers and DOM runtime artifacts...');

      // Get cached headers from background
      let headers = {};
      try {
        const headerRes = await chrome.runtime.sendMessage({
          action: 'GET_CACHED_HEADERS',
          tabId: tab.id,
          url: tab.url
        });
        if (headerRes && headerRes.data && headerRes.data.headers) {
          headers = headerRes.data.headers;
        }
      } catch (e) {
        console.warn('Headers fetch notice:', e);
      }
      state.headers = headers;

      // Collect page data: Try content-script first, with executeScript fallback
      let pageData = null;

      try {
        const dataRes = await chrome.tabs.sendMessage(tab.id, { action: 'COLLECT_PAGE_DATA' });
        if (dataRes && dataRes.pageData) {
          pageData = dataRes.pageData;
        }
      } catch (e) {
        // Content script not ready or page unrefreshed, fallback to scripting.executeScript below
      }

      // If content-script didn't respond, run in-page extraction via scripting API
      if (!pageData) {
        try {
          const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
              const meta = {};
              document.querySelectorAll('meta').forEach(t => {
                const name = t.getAttribute('name') || t.getAttribute('property') || t.getAttribute('http-equiv');
                const content = t.getAttribute('content');
                if (name && content) meta[name.toLowerCase()] = content;
              });
              const scripts = [];
              document.querySelectorAll('script[src]').forEach(s => {
                const src = s.getAttribute('src');
                if (src) {
                  try { scripts.push(new URL(src, window.location.href).href); }
                  catch(e) { scripts.push(src); }
                }
              });
              const links = [];
              document.querySelectorAll('link[href]').forEach(l => {
                const href = l.getAttribute('href');
                if (href) {
                  try { links.push(new URL(href, window.location.href).href); }
                  catch(e) { links.push(href); }
                }
              });
              const resources = [];
              try {
                if (window.performance && typeof window.performance.getEntriesByType === 'function') {
                  const entries = window.performance.getEntriesByType('resource');
                  for (let i = 0; i < Math.min(entries.length, 120); i++) {
                    if (entries[i].name) resources.push(entries[i].name);
                  }
                }
              } catch(e) {}
              const combinedScriptUrls = Array.from(new Set([
                ...scripts,
                ...resources.filter(r => r.endsWith('.js') || r.includes('.js?') || r.includes('/js/') || r.includes('script'))
              ]));
              const testSelectors = [
                '[data-reactroot]', '[data-reactid]', '#___gatsby', '#wpadminbar',
                '[ng-version]', '[_nghost-[a-z0-9]+]', '[data-v-[a-z0-9]+]', '#__nuxt',
                'script#__NEXT_DATA__', '[x-data]', '[x-init]', '[class*="svelte-"]',
                'link[rel*="https://api.w.org/"]', 'script[data-drupal-selector]',
                '.ghost-portal-root', '[data-bs-toggle]', '[data-bs-target]',
                '#django-admin-prepopulated-fields-constants', 'astro-island',
                '[data-wf-site]', '.cf-turnstile', '.g-recaptcha', '.h-captcha', 'link[rel="manifest"]'
              ];
              const selectors = [];
              testSelectors.forEach(sel => {
                try { if (document.querySelector(sel)) selectors.push(sel); } catch(e) {}
              });
              const cssSignatures = [];
              try {
                if (document.querySelector('[class*="tw-"], [class*="max-w-"], [class*="min-h-"]')) cssSignatures.push('tailwind');
                if (document.querySelector('.container-fluid, .row, .col-md-, .btn-primary')) cssSignatures.push('bootstrap');
                if (document.querySelector('[class*="MuiButton-"], [class*="MuiBox-"], [class*="MuiTypography-"]')) cssSignatures.push('material-ui');
                if (document.querySelector('[class*="chakra-"]')) cssSignatures.push('chakra-ui');
                if (document.querySelector('[class*="ant-"]')) cssSignatures.push('ant-design');
                if (document.querySelector('.is-primary, .navbar-item, .has-text-centered')) cssSignatures.push('bulma');
                if (document.querySelector('.fa, .fas, .fab, .far, [class*="fa-"]')) cssSignatures.push('font-awesome');
              } catch(e) {}
              const pwa = {
                hasManifest: !!document.querySelector('link[rel="manifest"]'),
                hasServiceWorker: !!(navigator.serviceWorker && navigator.serviceWorker.controller),
                themeColor: meta['theme-color'] || null,
                hasAppleTouchIcon: !!document.querySelector('link[rel="apple-touch-icon"]')
              };
              const cookies = [];
              try {
                (document.cookie ? document.cookie.split(';') : []).forEach(c => {
                  const k = c.trim().split('=')[0];
                  if (k) cookies.push(k);
                });
              } catch(e) {}
              let html = '';
              try { html = (document.documentElement ? document.documentElement.outerHTML : '').slice(0, 40000); } catch(e) {}
              return {
                url: window.location.href,
                title: document.title,
                meta,
                scripts,
                links,
                resources,
                combinedScriptUrls,
                selectors,
                cssSignatures,
                pwa,
                cookies,
                html,
                globals: {}
              };
            }
          });
          if (results && results[0] && results[0].result) {
            pageData = results[0].result;
          }
        } catch (err) {}
      }

      // Read or supplement MAIN world globals directly across all 14 categories
      try {
        const globalResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: () => {
            const g = {};
            try {
              // 1. JavaScript Frameworks
              if (window.React) {
                g['React'] = true;
                if (window.React.version) g['React.version'] = String(window.React.version);
              }
              if (window.ReactDOM && window.ReactDOM.version) g['ReactDOM.version'] = String(window.ReactDOM.version);
              if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) g['__REACT_DEVTOOLS_GLOBAL_HOOK__'] = true;
              if (window.__NEXT_DATA__) {
                g['__NEXT_DATA__'] = true;
                if (window.__NEXT_DATA__.buildId) g['__NEXT_DATA__.buildId'] = String(window.__NEXT_DATA__.buildId);
              }
              if (window.__next) g['__next'] = true;
              if (window.Vue) {
                g['Vue'] = true;
                if (window.Vue.version) g['Vue.version'] = String(window.Vue.version);
              }
              if (window.__VUE__) g['__VUE__'] = true;
              if (window.__NUXT__) g['__NUXT__'] = true;
              if (window.angular) {
                g['angular'] = true;
                if (window.angular.version && window.angular.version.full) g['angular.version.full'] = String(window.angular.version.full);
              }
              if (window.ng) g['ng'] = true;
              if (window.Alpine) {
                g['Alpine'] = true;
                if (window.Alpine.version) g['Alpine.version'] = String(window.Alpine.version);
              }
              if (window.__svelte) g['__svelte'] = true;
              if (window.__remixContext) g['__remixContext'] = true;
              if (window.___gatsby) g['___gatsby'] = true;
              if (window._$HY) g['SolidJS'] = true;
              if (window.Ember || window.Em) g['Ember'] = true;
              if (window.__preact) g['Preact'] = true;

              // 2. JavaScript Libraries
              if (window.jQuery) {
                g['jQuery'] = true;
                if (window.jQuery.fn && window.jQuery.fn.jquery) g['jQuery.fn.jquery'] = String(window.jQuery.fn.jquery);
              } else if (window.$ && window.$.fn && window.$.fn.jquery) {
                g['$.fn.jquery'] = String(window.$.fn.jquery);
              }
              if (window.bootstrap) {
                g['bootstrap'] = true;
                if (window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) g['bootstrap.Tooltip.VERSION'] = String(window.bootstrap.Tooltip.VERSION);
              }
              if (window._ && window._.VERSION) g['_.VERSION'] = String(window._.VERSION);
              if (window.axios && window.axios.VERSION) g['axios.VERSION'] = String(window.axios.VERSION);
              if (window.moment && window.moment.version) g['moment.version'] = String(window.moment.version);
              if (window.dayjs) g['dayjs'] = true;
              if (window['__core-js_shared__']) g['core-js'] = true;
              if (window.rxjs) g['rxjs'] = true;
              if (window.THREE && window.THREE.REVISION) g['THREE.REVISION'] = String(window.THREE.REVISION);
              if (window.Chart && window.Chart.version) g['Chart.version'] = String(window.Chart.version);
              if (window.d3 && window.d3.version) g['d3.version'] = String(window.d3.version);
              if (window.Modernizr) g['Modernizr'] = true;

              // 3. CMS Globals
              if (window.wp) g['wp'] = true;
              if (window._wpemojiSettings) g['_wpemojiSettings'] = true;
              if (window.Drupal) g['Drupal'] = true;
              if (window.Joomla) g['Joomla'] = true;
              if (window.Shopify) g['Shopify'] = true;
              if (window.ghost) g['ghost'] = true;
              if (window.Webflow) g['Webflow'] = true;

              // 4. Analytics & RUM Globals
              if (window.ga || window.gtag) g['ga'] = true;
              if (window.google_tag_manager) g['google_tag_manager'] = true;
              if (window._paq) g['_paq'] = true;
              if (window.plausible) g['plausible'] = true;
              if (window.analytics && typeof window.analytics.identify === 'function') g['Segment'] = true;
              if (window.mixpanel) g['mixpanel'] = true;
              if (window.hj) g['Hotjar'] = true;
              if (window.__SENTRY__ || window.Sentry) {
                g['Sentry'] = true;
                if (window.Sentry && window.Sentry.SDK_VERSION) g['Sentry.SDK_VERSION'] = String(window.Sentry.SDK_VERSION);
              }
              if (window.DD_RUM) g['Datadog_RUM'] = true;
              if (window.clarity) g['Microsoft_Clarity'] = true;

              // 5. Advertising Globals
              if (window.adsbygoogle) g['Google_AdSense'] = true;
              if (window.googletag) g['Google_Publisher_Tag'] = true;
              if (window.fbq) g['Facebook_Pixel'] = true;
              if (window.criteo_q) g['Criteo'] = true;

              // 6. Security & Anti-Bot Globals
              if (window.turnstile) g['Cloudflare_Turnstile'] = true;
              if (window.grecaptcha) g['Google_reCAPTCHA'] = true;
              if (window.hcaptcha) g['hCaptcha'] = true;

              // 7. APIs & WebSockets Globals
              if (window.io) g['Socket.io'] = true;
              if (window.Pusher) g['Pusher'] = true;

              // 8. Bundlers & Performance Globals
              if (window.webpackChunk || window.webpackJsonp) g['webpack'] = true;
              if (window.__vite_plugin_react_preamble_installed__) g['Vite'] = true;
            } catch(e) {}
            return g;
          }
        });
        if (globalResults && globalResults[0] && globalResults[0].result) {
          if (!pageData) pageData = { globals: {} };
          pageData.globals = Object.assign({}, pageData.globals || {}, globalResults[0].result);
        }
      } catch (gErr) {}

      // If pageData is still null, construct minimal fallback
      if (!pageData) {
        pageData = {
          url: tab.url,
          title: tab.title || '',
          meta: {},
          scripts: [],
          links: [],
          selectors: [],
          cookies: [],
          html: '',
          globals: {}
        };
      }

      // Merge headers
      pageData.headers = headers;
      state.pageData = pageData;

      showLoading('Running fingerprint matching and security posture analysis...');

      // 1. Detect Technologies
      state.detectedTechnologies = window.SecurityAnalyzerDetector.detectTechnologies(
        pageData,
        state.fingerprints
      );

      // 2. Run Security Analyzer
      state.securityAudit = window.SecurityAnalyzerSecurityEngine.analyzeSecurity({
        url: tab.url,
        headers: headers,
        detectedTechnologies: state.detectedTechnologies,
        scripts: pageData.scripts
      });

      // 3. Query Vulnerability Intelligence
      state.vulnerabilities = window.SecurityAnalyzerVulnIntel.queryVulnerabilities(
        state.detectedTechnologies
      );

      // Update timestamp
      els.scanTimestamp.textContent = new Date().toLocaleTimeString();

      // Render UI
      renderOverview();
      renderTechnologies();
      renderVersions();
      renderSecurityFindings();
      renderVulnerabilities();

      hideLoading();

    } catch (err) {
      console.error('Audit execution error:', err);
      showError(`Analysis failed: ${err.message || 'Unknown error occurred.'}`);
    }
  }

  /**
   * Render 1. Overview Tab
   */
  function renderOverview() {
    const sec = state.securityAudit;
    const techs = state.detectedTechnologies;
    const vulns = state.vulnerabilities;

    // Header badge
    els.headerScoreBadge.textContent = `${sec.grade} (${sec.securityScore})`;
    els.headerScoreBadge.className = `score-badge grade-${sec.grade.toLowerCase()}`;

    // Overview Score circle
    els.overviewScoreNum.textContent = sec.securityScore;
    els.overviewGradeText.textContent = `Grade ${sec.grade}`;
    els.overviewGradeText.className = `grade-text grade-${sec.grade.toLowerCase()}`;

    let desc = 'Good Security Baseline';
    if (sec.grade === 'A') desc = 'Robust Security Posture';
    else if (sec.grade === 'B') desc = 'Satisfactory, minor improvements needed';
    else if (sec.grade === 'C') desc = 'Moderate gaps in security headers';
    else if (sec.grade === 'D') desc = 'Multiple critical security configurations missing';
    else if (sec.grade === 'F') desc = 'High exposure risk identified';
    els.overviewRatingDesc.textContent = desc;

    // Counter widgets
    els.cntTechs.textContent = techs.length;
    if (els.cntFindings) els.cntFindings.textContent = sec.findings.length;
    if (els.cntVulns) els.cntVulns.textContent = vulns.matches.length;

    // Filter and update Detected Programming Languages
    const languages = techs.filter(t => t.category === 'Programming Language');
    if (els.cntLanguages) els.cntLanguages.textContent = languages.length;

    // Render Prominent Language Summary Badges in Top Bar
    if (els.langBannerBadges) {
      els.langBannerBadges.innerHTML = '';
      const backendLangs = languages.filter(l => ['PHP', 'Python', 'Java', 'Ruby', 'C# (.NET)', 'Node.js', 'Go (Golang)'].includes(l.name));
      const frontendLangs = languages.filter(l => ['JavaScript', 'TypeScript'].includes(l.name));

      if (backendLangs.length > 0) {
        backendLangs.forEach(bl => {
          const span = document.createElement('span');
          span.className = 'lang-mini-badge badge-backend-lang';
          span.textContent = `Backend: ${bl.name}${bl.version ? ' ' + bl.version : ''}`;
          els.langBannerBadges.appendChild(span);
        });
      } else {
        const span = document.createElement('span');
        span.className = 'lang-mini-badge badge-masked-lang';
        span.textContent = 'Backend: Masked / Hidden';
        els.langBannerBadges.appendChild(span);
      }

      if (frontendLangs.length > 0) {
        frontendLangs.forEach(fl => {
          const span = document.createElement('span');
          span.className = 'lang-mini-badge badge-frontend-lang';
          span.textContent = `Frontend: ${fl.name}`;
          els.langBannerBadges.appendChild(span);
        });
      } else {
        const span = document.createElement('span');
        span.className = 'lang-mini-badge badge-frontend-lang';
        span.textContent = 'Frontend: JavaScript';
        els.langBannerBadges.appendChild(span);
      }
    }

    // Render Detailed Language Cards in Overview Tab
    if (els.overviewLanguageList) {
      els.overviewLanguageList.innerHTML = '';
      if (languages.length === 0) {
        els.overviewLanguageList.innerHTML = `
          <div class="language-item lang-frontend">
            <div class="language-item-header">
              <span class="language-name">JavaScript</span>
              <span class="language-role-tag role-frontend">Client-side Scripting</span>
            </div>
            <div class="language-evidence">
              <strong>Status:</strong> Active in browser DOM environment
            </div>
          </div>
          <div class="language-item" style="border-left-color: #64748b;">
            <div class="language-item-header">
              <span class="language-name" style="color: #94a3b8;">Backend Language Masked</span>
              <span class="language-role-tag" style="background: rgba(100,116,139,0.2); color: #cbd5e1;">Protected</span>
            </div>
            <div class="language-evidence">
              <strong>Reason:</strong> Server does not expose public X-Powered-By or language banners (recommended security practice).
            </div>
          </div>
        `;
      } else {
        languages.forEach(lang => {
          const item = document.createElement('div');
          const isBackend = ['PHP', 'Python', 'Java', 'Ruby', 'C# (.NET)', 'Node.js', 'Go (Golang)'].includes(lang.name);
          item.className = `language-item ${isBackend ? 'lang-backend' : 'lang-frontend'}`;

          const roleLabel = isBackend ? 'Backend Runtime' : 'Client-side Scripting';
          const roleClass = isBackend ? 'role-backend' : 'role-frontend';
          const primaryEvidence = (lang.evidence && lang.evidence[0]) ? lang.evidence[0].detail : lang.detectionMethod;

          item.innerHTML = `
            <div class="language-item-header">
              <span class="language-name">
                <span>${escapeHtml(lang.name)}</span>
                ${lang.version ? `<span class="ver-tag tag-${lang.versionStatus.toLowerCase()}">${escapeHtml(lang.version)} (${lang.versionStatus})</span>` : `<span class="ver-tag tag-${lang.versionStatus.toLowerCase()}">${lang.versionStatus}</span>`}
              </span>
              <span class="language-role-tag ${roleClass}">${roleLabel}</span>
            </div>
            <div class="language-evidence">
              <strong>Evidence:</strong> <code>${escapeHtml(primaryEvidence)}</code>
            </div>
          `;
          els.overviewLanguageList.appendChild(item);
        });
      }
    }

    els.techBadge.textContent = techs.length;
    els.secBadge.textContent = sec.findings.length;
    els.vulnBadge.textContent = vulns.matches.length;

    // Severity breakdown
    els.sevCntCritical.textContent = sec.stats.Critical;
    els.sevCntHigh.textContent = sec.stats.High;
    els.sevCntMedium.textContent = sec.stats.Medium;
    els.sevCntLow.textContent = sec.stats.Low;
    els.sevCntInfo.textContent = sec.stats.Informational;

    // Identified Core Stack pills
    els.overviewStackList.innerHTML = '';
    if (techs.length === 0) {
      els.overviewStackList.innerHTML = '<span class="empty-hint">No definitive technology fingerprints detected.</span>';
    } else {
      techs.forEach(t => {
        const pill = document.createElement('div');
        pill.className = 'stack-pill';
        pill.innerHTML = `
          <span>${escapeHtml(t.name)}</span>
          ${t.version ? `<span class="stack-pill-ver">${escapeHtml(t.version)}</span>` : ''}
        `;
        els.overviewStackList.appendChild(pill);
      });
    }
  }

  /**
   * Render 2. Technologies Tab
   */
  function renderTechnologies() {
    const container = els.techsListContainer;
    container.innerHTML = '';

    const query = (els.techSearchInput.value || '').toLowerCase().trim();
    const cat = els.techCategoryFilter.value;

    const filtered = state.detectedTechnologies.filter(t => {
      const matchQuery = !query || t.name.toLowerCase().includes(query) || (t.version && t.version.toLowerCase().includes(query));
      const matchCat = cat === 'ALL' || t.category === cat;
      return matchQuery && matchCat;
    });

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-hint">No technologies match current filter criteria.</div>';
      return;
    }

    filtered.forEach(tech => {
      const card = document.createElement('div');
      card.className = 'item-card';

      const evidenceHtml = tech.evidence.map(e => 
        `<div><span class="evidence-label">[${escapeHtml(e.type)}]</span> ${escapeHtml(e.detail)}</div>`
      ).join('');

      const limitationHtml = tech.uncertainties && tech.uncertainties.length > 0
        ? `<div class="limitation-box">⚠️ ${escapeHtml(tech.uncertainties.join(' '))}</div>`
        : '';

      card.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span>${escapeHtml(tech.name)}</span>
            <span class="category-tag">${escapeHtml(tech.category)}</span>
            ${tech.version ? `<span class="ver-tag tag-${tech.versionStatus.toLowerCase()}">${escapeHtml(tech.version)} (${tech.versionStatus})</span>` : ''}
          </div>
          <div class="confidence-bar-wrap" title="Confidence Score: ${tech.confidence}%">
            <span>${tech.confidence}%</span>
            <div class="confidence-track">
              <div class="confidence-fill" style="width: ${tech.confidence}%"></div>
            </div>
          </div>
        </div>
        <div class="card-desc">${escapeHtml(tech.description || '')}</div>
        <div class="evidence-drawer">
          ${evidenceHtml}
        </div>
        ${limitationHtml}
      `;
      container.appendChild(card);
    });
  }

  /**
   * Render 3. Versions Tab
   */
  function renderVersions() {
    const container = els.versionsListContainer;
    container.innerHTML = '';

    if (state.detectedTechnologies.length === 0) {
      container.innerHTML = '<div class="empty-hint">No detected software components available for version analysis.</div>';
      return;
    }

    state.detectedTechnologies.forEach(t => {
      const card = document.createElement('div');
      card.className = 'item-card';

      let statusDesc = '';
      if (t.versionStatus === 'Exact') {
        statusDesc = 'Confirmed by explicit runtime object or version declaration.';
      } else if (t.versionStatus === 'Inferred') {
        statusDesc = t.versionLimitation || 'Inferred from resource filenames or heuristic query parameters.';
      } else if (t.versionStatus === 'Partial') {
        statusDesc = 'Identified major or minor branch; exact patch level is unexposed.';
      } else {
        statusDesc = 'Technology fingerprint verified, but version is not publicly disclosed.';
      }

      card.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span>${escapeHtml(t.name)}</span>
            <span class="category-tag">${escapeHtml(t.category)}</span>
          </div>
          <span class="ver-tag tag-${t.versionStatus.toLowerCase()}">${t.version || 'Unknown'} — ${t.versionStatus}</span>
        </div>
        <div class="card-desc">${escapeHtml(statusDesc)}</div>
        <div class="evidence-drawer">
          <span class="evidence-label">Primary Signal:</span> ${escapeHtml(t.detectionMethod)}
        </div>
      `;
      container.appendChild(card);
    });
  }

  /**
   * Render 4. Security Findings Tab
   */
  function renderSecurityFindings() {
    const container = els.securityListContainer;
    container.innerHTML = '';

    const query = (els.secSearchInput.value || '').toLowerCase().trim();
    const sev = els.secSeverityFilter.value;

    const findings = state.securityAudit?.findings || [];
    const filtered = findings.filter(f => {
      const matchQuery = !query || f.title.toLowerCase().includes(query) || f.description.toLowerCase().includes(query);
      const matchSev = sev === 'ALL' || f.severity === sev;
      return matchQuery && matchSev;
    });

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-hint">No security findings matching current filters.</div>';
      return;
    }

    filtered.forEach(f => {
      const card = document.createElement('div');
      card.className = `item-card finding-card sev-${f.severity}`;

      card.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span class="finding-badge badge-${f.severity}">${escapeHtml(f.severity)}</span>
            <span>${escapeHtml(f.title)}</span>
          </div>
          <span class="category-tag">${escapeHtml(f.category)}</span>
        </div>
        <div class="card-desc">${escapeHtml(f.description)}</div>
        <div class="evidence-drawer">
          <span class="evidence-label">Evidence:</span> ${escapeHtml(f.evidence)}
        </div>
        <div class="impact-box">
          <span class="box-title">Potential Impact:</span> ${escapeHtml(f.impact)}
        </div>
        <div class="remediation-box">
          <span class="box-title">Remediation:</span> ${escapeHtml(f.remediation)}
        </div>
      `;
      container.appendChild(card);
    });
  }

  /**
   * Render 5. Vulnerability Intelligence Tab
   */
  function renderVulnerabilities() {
    const container = els.vulnListContainer;
    container.innerHTML = '';

    const intel = state.vulnerabilities;
    if (!intel || intel.matches.length === 0) {
      container.innerHTML = `
        <div class="item-card text-center" style="padding: 20px;">
          <div style="color: var(--accent-green-bright); font-size: 20px; margin-bottom: 6px;">✓</div>
          <h4 style="color: #fff; margin-bottom: 4px;">No Immediate CVE Matches Found</h4>
          <p class="card-desc">No known high-impact CVEs in the curated vulnerability intelligence database matched the fingerprinted versions on this page.</p>
        </div>
      `;
      return;
    }

    intel.matches.forEach(m => {
      const card = document.createElement('div');
      card.className = 'item-card finding-card sev-' + m.severity;

      card.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span class="finding-badge badge-${m.severity}">${escapeHtml(m.severity)}</span>
            <span style="font-family: var(--font-mono);">${escapeHtml(m.cveId)}</span>
            <span class="cvss-score-pill cvss-${m.severity.toLowerCase()}">CVSS ${m.cvssScore}</span>
          </div>
          <span class="category-tag">${escapeHtml(m.techName)} ${escapeHtml(m.detectedVersion)}</span>
        </div>
        <h4 style="font-size: 12px; color: #fff; margin: 4px 0;">${escapeHtml(m.title)}</h4>
        <div class="card-desc">${escapeHtml(m.description)}</div>
        <div class="remediation-box">
          <span class="box-title">Remediation Advisory:</span> ${escapeHtml(m.remediation)}
        </div>
        <div class="limitation-box">
          ℹ️ <strong>Status Note:</strong> ${escapeHtml(m.disclaimer)}
        </div>
        <div style="margin-top: 6px; font-size: 10px;">
          <a href="${escapeHtml(m.reference)}" target="_blank" style="color: var(--accent-green-bright); text-decoration: none;">View NVD Vulnerability Advisory &rarr;</a>
        </div>
      `;
      container.appendChild(card);
    });
  }

  /**
   * 6. Deep Scan Action
   */
  async function startDeepScan() {
    if (!state.deepScanner) {
      alert('Deep Scanner module is unavailable.');
      return;
    }

    els.startDeepScanBtn.classList.add('hidden');
    els.cancelDeepScanBtn.classList.remove('hidden');
    els.deepScanProgressBox.classList.remove('hidden');
    els.deepProgressBar.style.width = '10%';
    els.deepProgressStatus.textContent = 'Initializing non-destructive deep probes...';
    els.deepScanResultsContainer.innerHTML = '';

    const scriptUrls = state.pageData?.scripts || [];

    try {
      const results = await state.deepScanner.scan(
        state.targetUrl,
        scriptUrls,
        (progress, statusText) => {
          els.deepProgressBar.style.width = `${progress}%`;
          els.deepProgressStatus.textContent = statusText;
        }
      );

      state.deepScanResults = results;
      renderDeepScanResults(results);

    } catch (err) {
      els.deepScanResultsContainer.innerHTML = `<div class="limitation-box">Deep Scan encountered an error: ${escapeHtml(err.message)}</div>`;
    } finally {
      els.startDeepScanBtn.classList.remove('hidden');
      els.cancelDeepScanBtn.classList.add('hidden');
    }
  }

  function cancelDeepScan() {
    if (state.deepScanner) {
      state.deepScanner.cancel();
      els.deepProgressStatus.textContent = 'Scan cancelled by user.';
      els.startDeepScanBtn.classList.remove('hidden');
      els.cancelDeepScanBtn.classList.add('hidden');
    }
  }

  function renderDeepScanResults(results) {
    const container = els.deepScanResultsContainer;
    container.innerHTML = '';

    if (results.canceled) {
      container.innerHTML = '<div class="limitation-box">Deep Scan was cancelled by user.</div>';
      return;
    }

    // 1. security.txt result
    const secTxtCard = document.createElement('div');
    secTxtCard.className = 'item-card';
    if (results.securityTxt && results.securityTxt.found) {
      secTxtCard.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span class="finding-badge badge-Informational">RFC 9116</span>
            <span>Security Contact File (security.txt)</span>
          </div>
          <span class="ver-tag tag-exact">Present</span>
        </div>
        <div class="card-desc">Verified at: ${escapeHtml(results.securityTxt.location)}</div>
        <div class="evidence-drawer">Contacts: ${escapeHtml(results.securityTxt.contacts.join(', ') || 'Declared')}</div>
      `;
    } else {
      secTxtCard.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span class="finding-badge badge-Informational">RFC 9116</span>
            <span>Security Contact File (security.txt)</span>
          </div>
          <span class="ver-tag tag-unknown">Missing</span>
        </div>
        <div class="card-desc">No RFC 9116 security.txt was discovered at standard well-known endpoints.</div>
      `;
    }
    container.appendChild(secTxtCard);

    // 2. robots.txt result
    const robotsCard = document.createElement('div');
    robotsCard.className = 'item-card';
    if (results.robotsTxt && results.robotsTxt.found) {
      const paths = results.robotsTxt.sensitivePaths;
      robotsCard.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span class="finding-badge badge-Low">ROBOTS.TXT</span>
            <span>Administrative Path Disclosures</span>
          </div>
          <span class="ver-tag tag-partial">${paths.length} Sensitive Path(s)</span>
        </div>
        <div class="card-desc">The robots.txt file was parsed for potentially sensitive disallow rules.</div>
        <div class="evidence-drawer">${paths.length > 0 ? escapeHtml(paths.join(', ')) : 'No obvious administrative keywords in disallow directives.'}</div>
      `;
    } else {
      robotsCard.innerHTML = `
        <div class="card-header-row">
          <div class="card-title">
            <span class="finding-badge badge-Informational">ROBOTS.TXT</span>
            <span>Robots Exclusion File</span>
          </div>
          <span class="ver-tag tag-unknown">Not Found</span>
        </div>
        <div class="card-desc">No robots.txt was returned by the host.</div>
      `;
    }
    container.appendChild(robotsCard);

    // 3. Script Banners
    if (results.scriptBanners && results.scriptBanners.length > 0) {
      results.scriptBanners.forEach(b => {
        const bCard = document.createElement('div');
        bCard.className = 'item-card';
        bCard.innerHTML = `
          <div class="card-header-row">
            <div class="card-title">
              <span class="finding-badge badge-Informational">SCRIPT BANNER</span>
              <span>${escapeHtml(b.library || 'Comment Banner')} ${b.version ? `v${escapeHtml(b.version)}` : ''}</span>
            </div>
          </div>
          <div class="card-desc">Resource: ${escapeHtml(b.url.slice(0, 70))}...</div>
          <div class="evidence-drawer">${escapeHtml(b.banner)}</div>
        `;
        container.appendChild(bCard);
      });
    }
  }

  /**
   * 7. Export Reports
   */
  function exportJsonReport() {
    if (!state.securityAudit) {
      alert('Please wait for page analysis to complete before exporting.');
      return;
    }

    const reportObj = window.SecurityAnalyzerReporter.generateJsonReport({
      url: state.targetUrl,
      timestamp: new Date().toISOString(),
      securityScore: state.securityAudit.securityScore,
      grade: state.securityAudit.grade,
      technologies: state.detectedTechnologies,
      securityFindings: state.securityAudit.findings,
      vulnerabilities: state.vulnerabilities.matches,
      deepScanResults: state.deepScanResults
    });

    const jsonStr = JSON.stringify(reportObj, null, 2);
    const host = new URL(state.targetUrl).hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const filename = `security-analyzer-${host}-${Date.now()}.json`;

    window.SecurityAnalyzerReporter.triggerDownload(jsonStr, filename, 'application/json');
  }

  function exportCsvReport() {
    if (!state.securityAudit) {
      alert('Please wait for page analysis to complete before exporting.');
      return;
    }

    const csvStr = window.SecurityAnalyzerReporter.generateCsvReport({
      url: state.targetUrl,
      timestamp: new Date().toISOString(),
      securityScore: state.securityAudit.securityScore,
      grade: state.securityAudit.grade,
      technologies: state.detectedTechnologies,
      securityFindings: state.securityAudit.findings,
      vulnerabilities: state.vulnerabilities.matches
    });

    const host = new URL(state.targetUrl).hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const filename = `security-analyzer-${host}-${Date.now()}.csv`;

    window.SecurityAnalyzerReporter.triggerDownload(csvStr, filename, 'text/csv');
  }

  /**
   * 8. Settings Management
   */
  async function loadSettings() {
    try {
      const stored = await chrome.storage.local.get(['securityAnalyzerSettings']);
      if (stored && stored.securityAnalyzerSettings) {
        state.settings = Object.assign(state.settings, stored.securityAnalyzerSettings);
      }
    } catch (e) {}

    els.settingBackendUrl.value = state.settings.backendUrl || 'http://127.0.0.1:8000';
    els.settingUseBackend.checked = !!state.settings.useBackend;
    els.settingAutoScan.checked = state.settings.autoScan !== false;
    els.settingDeepTimeout.value = state.settings.deepTimeout || 10;

    // Check backend health
    checkBackendHealth(els.settingBackendUrl.value);
  }

  async function saveSettings() {
    state.settings.backendUrl = els.settingBackendUrl.value.trim();
    state.settings.useBackend = els.settingUseBackend.checked;
    state.settings.autoScan = els.settingAutoScan.checked;
    state.settings.deepTimeout = parseInt(els.settingDeepTimeout.value, 10) || 10;

    await chrome.storage.local.set({ securityAnalyzerSettings: state.settings });

    els.saveNotice.classList.remove('hidden');
    setTimeout(() => els.saveNotice.classList.add('hidden'), 2000);

    checkBackendHealth(state.settings.backendUrl);
  }

  async function checkBackendHealth(url) {
    try {
      const res = await chrome.runtime.sendMessage({
        action: 'CHECK_BACKEND_STATUS',
        backendUrl: url
      });
      if (res && res.available) {
        els.backendStatusPill.textContent = 'Backend Online (FastAPI)';
        els.backendStatusPill.className = 'status-pill pill-online';
      } else {
        els.backendStatusPill.textContent = 'Backend Offline';
        els.backendStatusPill.className = 'status-pill pill-offline';
      }
    } catch (e) {
      els.backendStatusPill.textContent = 'Backend Offline';
      els.backendStatusPill.className = 'status-pill pill-offline';
    }
  }

  // Helpers
  function showLoading(msg) {
    els.loadingMsg.textContent = msg;
    els.loadingState.classList.remove('hidden');
  }

  function hideLoading() {
    els.loadingState.classList.add('hidden');
  }

  function showError(msg) {
    hideLoading();
    els.errorMsg.textContent = msg;
    els.errorState.classList.remove('hidden');
  }

  function hideError() {
    els.errorState.classList.add('hidden');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
});
