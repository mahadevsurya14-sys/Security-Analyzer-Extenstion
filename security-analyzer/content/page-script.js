/**
 * Security Analyzer - Page Runtime Inspector (MAIN world context)
 * Safely inspects window globals and runtime objects across all technology categories.
 */

(function () {
  'use strict';

  function safeInspect() {
    const globals = {};

    try {
      // 1. JavaScript Frameworks
      if (window.React) {
        globals['React'] = true;
        if (window.React.version) globals['React.version'] = String(window.React.version);
      }
      if (window.ReactDOM && window.ReactDOM.version) {
        globals['ReactDOM.version'] = String(window.ReactDOM.version);
      }
      if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) globals['__REACT_DEVTOOLS_GLOBAL_HOOK__'] = true;

      if (window.__NEXT_DATA__) {
        globals['__NEXT_DATA__'] = true;
        if (window.__NEXT_DATA__.buildId) globals['__NEXT_DATA__.buildId'] = String(window.__NEXT_DATA__.buildId);
      }
      if (window.__next) globals['__next'] = true;

      if (window.Vue) {
        globals['Vue'] = true;
        if (window.Vue.version) globals['Vue.version'] = String(window.Vue.version);
      }
      if (window.__VUE__) globals['__VUE__'] = true;
      if (window.__NUXT__) globals['__NUXT__'] = true;

      if (window.angular) {
        globals['angular'] = true;
        if (window.angular.version && window.angular.version.full) {
          globals['angular.version.full'] = String(window.angular.version.full);
        }
      }
      if (window.ng) globals['ng'] = true;

      if (window.Alpine) {
        globals['Alpine'] = true;
        if (window.Alpine.version) globals['Alpine.version'] = String(window.Alpine.version);
      }

      if (window.__svelte) globals['__svelte'] = true;
      if (window.__remixContext) globals['__remixContext'] = true;
      if (window.___gatsby) globals['___gatsby'] = true;
      if (window._$HY) globals['SolidJS'] = true;
      if (window.Ember || window.Em) globals['Ember'] = true;
      if (window.__preact) globals['Preact'] = true;

      // 2. JavaScript Libraries
      if (window.jQuery) {
        globals['jQuery'] = true;
        if (window.jQuery.fn && window.jQuery.fn.jquery) {
          globals['jQuery.fn.jquery'] = String(window.jQuery.fn.jquery);
        }
      } else if (window.$ && window.$.fn && window.$.fn.jquery) {
        globals['$.fn.jquery'] = String(window.$.fn.jquery);
      }

      if (window.bootstrap) {
        globals['bootstrap'] = true;
        if (window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) {
          globals['bootstrap.Tooltip.VERSION'] = String(window.bootstrap.Tooltip.VERSION);
        }
      }

      if (window._) {
        globals['_'] = true;
        if (window._.VERSION) globals['_.VERSION'] = String(window._.VERSION);
      }

      if (window.axios) {
        globals['axios'] = true;
        if (window.axios.VERSION) globals['axios.VERSION'] = String(window.axios.VERSION);
      }

      if (window.moment) {
        globals['moment'] = true;
        if (window.moment.version) globals['moment.version'] = String(window.moment.version);
      }

      if (window.dayjs) globals['dayjs'] = true;
      if (window['__core-js_shared__']) globals['core-js'] = true;
      if (window.rxjs) globals['rxjs'] = true;
      if (window.THREE) {
        globals['THREE'] = true;
        if (window.THREE.REVISION) globals['THREE.REVISION'] = String(window.THREE.REVISION);
      }
      if (window.Chart) {
        globals['Chart'] = true;
        if (window.Chart.version) globals['Chart.version'] = String(window.Chart.version);
      }
      if (window.d3) {
        globals['d3'] = true;
        if (window.d3.version) globals['d3.version'] = String(window.d3.version);
      }
      if (window.Modernizr) globals['Modernizr'] = true;

      // 3. CMS & E-commerce Globals
      if (window.wp) globals['wp'] = true;
      if (window._wpemojiSettings) globals['_wpemojiSettings'] = true;
      if (window.Drupal) globals['Drupal'] = true;
      if (window.Joomla) globals['Joomla'] = true;
      if (window.Shopify) globals['Shopify'] = true;
      if (window.ghost) globals['ghost'] = true;
      if (window.Webflow) globals['Webflow'] = true;

      // 4. Analytics & RUM Globals
      if (window.ga) globals['ga'] = true;
      if (window.gtag) globals['gtag'] = true;
      if (window.google_tag_manager) globals['google_tag_manager'] = true;
      if (window._paq) globals['_paq'] = true; // Matomo
      if (window.plausible) globals['plausible'] = true;
      if (window.analytics && typeof window.analytics.identify === 'function') globals['Segment'] = true;
      if (window.mixpanel) globals['mixpanel'] = true;
      if (window.hj) globals['Hotjar'] = true;
      if (window.__SENTRY__ || window.Sentry) {
        globals['Sentry'] = true;
        if (window.Sentry && window.Sentry.SDK_VERSION) {
          globals['Sentry.SDK_VERSION'] = String(window.Sentry.SDK_VERSION);
        }
      }
      if (window.DD_RUM) globals['Datadog_RUM'] = true;
      if (window.clarity) globals['Microsoft_Clarity'] = true;

      // 5. Advertising Globals
      if (window.adsbygoogle) globals['Google_AdSense'] = true;
      if (window.googletag) globals['Google_Publisher_Tag'] = true;
      if (window.fbq) globals['Facebook_Pixel'] = true;
      if (window.criteo_q) globals['Criteo'] = true;

      // 6. Security & Anti-Bot Globals
      if (window.turnstile) globals['Cloudflare_Turnstile'] = true;
      if (window.grecaptcha) globals['Google_reCAPTCHA'] = true;
      if (window.hcaptcha) globals['hCaptcha'] = true;

      // 7. APIs & WebSockets Globals
      if (window.io) globals['Socket.io'] = true;
      if (window.Pusher) globals['Pusher'] = true;

      // 8. Bundlers & Performance Globals
      if (window.webpackChunk || window.webpackJsonp) globals['webpack'] = true;
      if (window.__vite_plugin_react_preamble_installed__) globals['Vite'] = true;

    } catch (e) {
      // Ignore security/cross-origin property access restrictions
    }

    // Broadcast discovered globals via custom DOM event for content script
    window.dispatchEvent(new CustomEvent('SECURITY_ANALYZER_GLOBALS_DISCOVERED', {
      detail: globals
    }));
  }

  // Run on initial load and listen for probe triggers
  safeInspect();
  window.addEventListener('SECURITY_ANALYZER_PROBE_GLOBALS_REQUEST', safeInspect);
})();
