/**
 * Security Analyzer - Wappalyzer-Grade Modular Technology Detection Engine
 * Evaluates DOM elements, script URLs, resource timings, meta tags, CSS signatures,
 * cookies, runtime window globals, and HTTP headers.
 * 
 * Strict Principle:
 * Identifies versions only from reliable version evidence.
 * Never invents versions or treats framework detection as proof of a programming language.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const versionDetector = require('./version-detector');
    module.exports = factory(versionDetector);
  } else {
    root.SecurityAnalyzerDetector = factory(root.SecurityAnalyzerVersionDetector);
  }
})(typeof self !== 'undefined' ? self : this, function (versionDetector) {
  'use strict';

  /**
   * Main detection function.
   * @param {object} pageData - Collected page artifacts
   * @param {object} fingerprintsDatabase - The parsed fingerprints.json object
   * @returns {Array<object>} List of deduplicated detected technologies with evidence
   */
  function detectTechnologies(pageData, fingerprintsDatabase) {
    if (!fingerprintsDatabase || !Array.isArray(fingerprintsDatabase.technologies)) {
      return [];
    }

    const {
      url = '',
      headers = {},
      cookies = [],
      meta = {},
      scripts = [],
      links = [],
      resources = [],
      selectors = [],
      cssSignatures = [],
      pwa = {},
      html = '',
      globals = {}
    } = pageData;

    // Normalize headers to lowercase
    const normalizedHeaders = {};
    Object.keys(headers || {}).forEach(k => {
      normalizedHeaders[k.toLowerCase()] = String(headers[k]);
    });

    // Normalize cookies set
    const cookieSet = new Set((cookies || []).map(c => typeof c === 'string' ? c.split('=')[0].trim() : c.name));

    // Combined script and resource URLs for inspection
    const allScriptUrls = Array.from(new Set([...scripts, ...resources]));

    const detected = [];
    const seenTechIds = new Set();

    for (const tech of fingerprintsDatabase.technologies) {
      if (seenTechIds.has(tech.id)) continue;

      const matchEvidence = [];
      let detectedVersion = null;
      let primaryMethod = null;
      let versionMethod = null;
      let baseConfidence = tech.confidence || 85;

      const rules = tech.rules || {};

      // 1. Inspect HTTP Response Headers
      if (rules.headers) {
        for (const [headerName, pattern] of Object.entries(rules.headers)) {
          const headerValue = normalizedHeaders[headerName.toLowerCase()];
          if (headerValue) {
            try {
              const rx = new RegExp(pattern, 'i');
              const m = headerValue.match(rx);
              if (m) {
                matchEvidence.push({
                  type: 'HTTP Header',
                  detail: `Header "${headerName}: ${headerValue}" matched pattern "${pattern}"`,
                  confidence: 95
                });
                if (!primaryMethod) primaryMethod = 'HTTP Header';

                if (m[1] && !detectedVersion) {
                  detectedVersion = m[1];
                  versionMethod = 'http_header';
                }
              }
            } catch (e) {}
          }
        }
      }

      // 2. Inspect JavaScript Globals (MAIN World Runtime)
      if (rules.globals && Array.isArray(rules.globals)) {
        for (const g of rules.globals) {
          const path = g.path;
          if (globals && globals[path] !== undefined && globals[path] !== null) {
            const val = globals[path];
            matchEvidence.push({
              type: 'Runtime Global',
              detail: `Window runtime object "window.${path}" detected`,
              confidence: 95
            });
            if (!primaryMethod) primaryMethod = 'Runtime Global';

            if (g.versionPath && globals[g.versionPath]) {
              detectedVersion = String(globals[g.versionPath]);
              versionMethod = 'runtime_global';
            } else if (typeof val === 'string' && /^\d+\.\d+/.test(val)) {
              detectedVersion = val;
              versionMethod = 'runtime_global';
            }
          }
        }
      }

      // 3. Inspect HTML Meta Tags
      if (rules.meta) {
        for (const [metaName, pattern] of Object.entries(rules.meta)) {
          const metaValue = meta[metaName.toLowerCase()];
          if (metaValue) {
            try {
              const rx = new RegExp(pattern, 'i');
              const m = metaValue.match(rx);
              if (m) {
                matchEvidence.push({
                  type: 'DOM Generator Meta',
                  detail: `Meta tag <meta name="${metaName}" content="${metaValue}"> matched`,
                  confidence: 92
                });
                if (!primaryMethod) primaryMethod = 'DOM Generator Meta';

                if (m[1] && !detectedVersion) {
                  detectedVersion = m[1];
                  versionMethod = 'meta_generator';
                }
              }
            } catch (e) {}
          }
        }
      }

      // 4. Inspect Script URLs & Dynamic Resource Timings
      if (rules.scripts && Array.isArray(rules.scripts)) {
        for (const scriptUrl of allScriptUrls) {
          for (const pattern of rules.scripts) {
            try {
              const rx = new RegExp(pattern, 'i');
              const m = scriptUrl.match(rx);
              if (m) {
                const shortUrl = scriptUrl.length > 75 ? scriptUrl.slice(0, 72) + '...' : scriptUrl;
                matchEvidence.push({
                  type: 'Script URL Pattern',
                  detail: `Asset URL matched: "${shortUrl}"`,
                  confidence: 88
                });
                if (!primaryMethod) primaryMethod = 'Script URL Pattern';

                if (m[1] && !detectedVersion) {
                  detectedVersion = m[1];
                  versionMethod = 'script_url';
                }
              }
            } catch (e) {}
          }
        }
      }

      // 5. Inspect Link Elements (Stylesheets, manifests, preconnects)
      if (rules.links && Array.isArray(rules.links)) {
        for (const linkUrl of links) {
          for (const pattern of rules.links) {
            try {
              const rx = new RegExp(pattern, 'i');
              if (rx.test(linkUrl)) {
                matchEvidence.push({
                  type: 'Link Tag',
                  detail: `Link href matched pattern: "${pattern}"`,
                  confidence: 85
                });
                if (!primaryMethod) primaryMethod = 'Link Tag';
              }
            } catch (e) {}
          }
        }
      }

      // 6. Inspect DOM Selectors
      if (rules.selectors && Array.isArray(rules.selectors)) {
        for (const sel of rules.selectors) {
          if (selectors.includes(sel)) {
            matchEvidence.push({
              type: 'DOM Selector',
              detail: `DOM signature matched selector: "${sel}"`,
              confidence: 85
            });
            if (!primaryMethod) primaryMethod = 'DOM Selector';
          }
        }
      }

      // 7. Inspect CSS Signatures (Class prefixes)
      if (rules.cssSignatures && Array.isArray(rules.cssSignatures)) {
        for (const sig of rules.cssSignatures) {
          if (cssSignatures.includes(sig)) {
            matchEvidence.push({
              type: 'CSS Class Signature',
              detail: `Page stylesheet classes contain signature: "${sig}"`,
              confidence: 82
            });
            if (!primaryMethod) primaryMethod = 'CSS Class Signature';
          }
        }
      }

      // 8. Inspect Cookies
      if (rules.cookies && Array.isArray(rules.cookies)) {
        for (const cookieName of rules.cookies) {
          if (cookieSet.has(cookieName)) {
            matchEvidence.push({
              type: 'Cookie Indicator',
              detail: `Session / tracking cookie identifier "${cookieName}" present`,
              confidence: 88
            });
            if (!primaryMethod) primaryMethod = 'Cookie Indicator';
          }
        }
      }

      // 9. Inspect PWA Indicators
      if (rules.pwa && pwa && (pwa.hasManifest || pwa.hasServiceWorker)) {
        matchEvidence.push({
          type: 'PWA Indicator',
          detail: `Web App Manifest (${pwa.hasManifest ? 'Yes' : 'No'}), Service Worker Controller (${pwa.hasServiceWorker ? 'Yes' : 'No'})`,
          confidence: 95
        });
        if (!primaryMethod) primaryMethod = 'PWA Indicator';
      }

      // 10. Inspect Specific HTML Patterns (Guarded to prevent false positives)
      if (rules.html && Array.isArray(rules.html) && html) {
        for (const pattern of rules.html) {
          try {
            const rx = new RegExp(pattern, 'i');
            if (rx.test(html)) {
              matchEvidence.push({
                type: 'HTML Pattern',
                detail: `Page markup matches signature pattern: "${pattern}"`,
                confidence: 75
              });
              if (!primaryMethod) primaryMethod = 'HTML Pattern';
            }
          } catch (e) {}
        }
      }

      // If matched, classify and deduplicate
      if (matchEvidence.length > 0) {
        seenTechIds.add(tech.id);

        let versionInfo = {
          version: null,
          status: 'Unknown',
          confidence: 0,
          limitation: 'No explicit version string was revealed in public assets or headers.'
        };

        if (detectedVersion && versionDetector) {
          versionInfo = versionDetector.classify(
            detectedVersion,
            versionMethod || 'heuristic',
            matchEvidence[0]?.detail || ''
          );
        }

        // Calculate consolidated confidence
        let finalConfidence = baseConfidence;
        if (matchEvidence.length >= 3) {
          finalConfidence = Math.min(99, finalConfidence + 10);
        } else if (matchEvidence.length === 1 && matchEvidence[0].type === 'HTML Pattern') {
          finalConfidence = Math.max(50, finalConfidence - 15);
        }

        const uncertainties = [];
        if (versionInfo.status === 'Inferred') {
          uncertainties.push(versionInfo.limitation || 'Version inferred from asset URL parameters or heuristic patterns.');
        } else if (versionInfo.status === 'Partial') {
          uncertainties.push('Exact patch/build version unknown; only major or minor branch identified.');
        } else if (versionInfo.status === 'Unknown') {
          uncertainties.push('Technology presence confirmed, but release version is masked or unobservable.');
        }

        detected.push({
          id: tech.id,
          name: tech.name,
          category: tech.category,
          description: tech.description,
          website: tech.website,
          version: versionInfo.version,
          versionStatus: versionInfo.status,
          versionConfidence: versionInfo.confidence,
          versionLimitation: versionInfo.limitation,
          confidence: finalConfidence,
          detectionMethod: primaryMethod || 'DOM Inspection',
          evidence: matchEvidence,
          uncertainties: uncertainties
        });
      }
    }

    return detected;
  }

  return {
    detectTechnologies
  };
});
