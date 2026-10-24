/**
 * Security Analyzer - Safe Deep Scanner Module
 * Performs user-initiated, non-destructive passive probes:
 * - RFC 9116 security.txt verification
 * - robots.txt administrative path disclosure audit
 * - Script asset banner and fingerprint inspection
 * - Safe concurrency and abort controls
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const versionDetector = require('./version-detector');
    module.exports = factory(versionDetector);
  } else {
    root.SecurityAnalyzerDeepScanner = factory(root.SecurityAnalyzerVersionDetector);
  }
})(typeof self !== 'undefined' ? self : this, function (versionDetector) {
  'use strict';

  class DeepScanner {
    constructor() {
      this.abortController = null;
      this.isRunning = false;
    }

    /**
     * Cancel an active deep scan
     */
    cancel() {
      if (this.abortController) {
        this.abortController.abort();
        this.abortController = null;
      }
      this.isRunning = false;
    }

    /**
     * Run the deep scan safely.
     * @param {string} targetUrl - Active tab URL
     * @param {Array<string>} scriptUrls - Discovered script URLs on page
     * @param {function} onProgress - Progress callback (percentage, statusText)
     * @returns {Promise<object>} Scan results
     */
    async scan(targetUrl, scriptUrls = [], onProgress = () => {}) {
      if (this.isRunning) {
        throw new Error('A Deep Scan is already in progress.');
      }

      this.isRunning = true;
      this.abortController = new AbortController();
      const signal = this.abortController.signal;

      const results = {
        targetUrl,
        startTime: new Date().toISOString(),
        securityTxt: null,
        robotsTxt: null,
        scriptBanners: [],
        deepFindings: [],
        completed: false,
        canceled: false
      };

      try {
        const parsed = new URL(targetUrl);
        const origin = parsed.origin;

        onProgress(15, 'Checking RFC 9116 security.txt...');
        if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

        // 1. Probe security.txt
        results.securityTxt = await this._checkSecurityTxt(origin, signal);
        if (results.securityTxt.found) {
          results.deepFindings.push({
            id: 'DEEP-SEC-TXT-FOUND',
            title: 'RFC 9116 Security Disclosure (security.txt) Present',
            severity: 'Informational',
            category: 'Vulnerability Disclosure',
            description: 'The website publishes a standard security.txt file declaring vulnerability reporting procedures.',
            evidence: `Found at: ${results.securityTxt.location} (Contacts: ${results.securityTxt.contacts.join(', ') || 'Declared'})`,
            impact: 'Enables ethical security researchers to report discovered vulnerabilities securely to the designated security team.',
            remediation: 'Keep security.txt contacts and GPG keys updated with current staff credentials.',
            confidence: 99
          });
        } else {
          results.deepFindings.push({
            id: 'DEEP-SEC-TXT-MISSING',
            title: 'Missing RFC 9116 security.txt File',
            severity: 'Informational',
            category: 'Vulnerability Disclosure',
            description: 'No security.txt file was found at /.well-known/security.txt or /security.txt.',
            evidence: 'HTTP 404/failure returned for standard security.txt endpoints.',
            impact: 'Security researchers discovering vulnerabilities may encounter difficulty identifying responsible contact channels.',
            remediation: 'Deploy a security.txt file at /.well-known/security.txt complying with RFC 9116 guidelines.',
            confidence: 95
          });
        }

        onProgress(40, 'Inspecting robots.txt for path disclosures...');
        if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

        // 2. Probe robots.txt
        results.robotsTxt = await this._checkRobotsTxt(origin, signal);
        if (results.robotsTxt.found && results.robotsTxt.sensitivePaths.length > 0) {
          results.deepFindings.push({
            id: 'DEEP-ROBOTS-SENSITIVE-PATHS',
            title: 'robots.txt Discloses Potentially Sensitive Paths',
            severity: 'Low',
            category: 'Information Disclosure',
            description: `The robots.txt file declares disallow rules pointing to administrative or internal routes (${results.robotsTxt.sensitivePaths.slice(0, 3).join(', ')}...).`,
            evidence: `Disallowed paths: ${results.robotsTxt.sensitivePaths.slice(0, 5).join(', ')}`,
            impact: 'robots.txt is public and often harvested by attackers during reconnaissance to map administrative panels, portal URLs, or hidden endpoints.',
            remediation: 'Ensure all disallowed administrative endpoints require strict multi-factor authentication, and avoid listing secret or obscure URL routes in public robots.txt files.',
            confidence: 90
          });
        }

        onProgress(70, 'Auditing public script headers & banners...');
        if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

        // 3. Inspect Script Asset Banners (limit to max 5 resources to prevent network congestion)
        const candidateScripts = scriptUrls
          .filter(u => typeof u === 'string' && !u.startsWith('data:') && !u.startsWith('blob:'))
          .slice(0, 5);

        for (let i = 0; i < candidateScripts.length; i++) {
          if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
          const scriptUrl = candidateScripts[i];
          const banner = await this._inspectScriptBanner(scriptUrl, signal);
          if (banner) {
            results.scriptBanners.push({
              url: scriptUrl,
              banner: banner.text,
              detectedLibrary: banner.library,
              version: banner.version
            });
          }
        }

        onProgress(100, 'Deep scan completed successfully.');
        results.completed = true;
        this.isRunning = false;
        return results;

      } catch (err) {
        this.isRunning = false;
        if (err.name === 'AbortError' || signal.aborted) {
          results.canceled = true;
          return results;
        }
        results.error = err.message || 'Unknown scan error';
        return results;
      }
    }

    /**
     * Checks RFC 9116 security.txt
     */
    async _checkSecurityTxt(origin, signal) {
      const paths = ['/.well-known/security.txt', '/security.txt'];
      for (const path of paths) {
        try {
          const res = await this._safeFetch(origin + path, signal, 3500);
          if (res && res.status === 200 && res.body) {
            const body = res.body;
            if (/Contact:\s*/i.test(body) || /Expires:\s*/i.test(body)) {
              const contacts = [];
              const lines = body.split('\n');
              for (const line of lines) {
                const m = line.match(/^Contact:\s*(.+)$/i);
                if (m) contacts.push(m[1].trim());
              }
              return {
                found: true,
                location: path,
                contacts: contacts,
                raw: body.slice(0, 500)
              };
            }
          }
        } catch (e) {
          // Continue to next path
        }
      }
      return { found: false, location: null, contacts: [] };
    }

    /**
     * Checks robots.txt for sensitive disallow routes
     */
    async _checkRobotsTxt(origin, signal) {
      try {
        const res = await this._safeFetch(origin + '/robots.txt', signal, 3500);
        if (res && res.status === 200 && res.body) {
          const sensitivePatterns = [
            /admin/i, /login/i, /dashboard/i, /wp-admin/i, /user/i,
            /api/i, /secret/i, /portal/i, /backend/i, /config/i
          ];
          const sensitivePaths = [];
          const lines = res.body.split('\n');
          for (const line of lines) {
            const m = line.match(/^Disallow:\s*(\S+)/i);
            if (m) {
              const path = m[1].trim();
              if (path && path !== '/' && sensitivePatterns.some(rx => rx.test(path))) {
                if (!sensitivePaths.includes(path)) {
                  sensitivePaths.push(path);
                }
              }
            }
          }
          return {
            found: true,
            totalDisallow: lines.filter(l => /^Disallow:/i.test(l)).length,
            sensitivePaths: sensitivePaths
          };
        }
      } catch (e) {}
      return { found: false, sensitivePaths: [] };
    }

    /**
     * Fetches first 2KB of a script to extract header comments / banners
     */
    async _inspectScriptBanner(url, signal) {
      try {
        const res = await this._safeFetch(url, signal, 3500, true);
        if (res && res.body) {
          // Look for comment banners: /*! ... */ or // ...
          const commentMatch = res.body.match(/\/\*![\s\S]*?\*\/|\/\*[\s\S]*?\*\//);
          if (commentMatch) {
            const bannerText = commentMatch[0].slice(0, 300);
            let library = null;
            let version = null;

            if (/jQuery/i.test(bannerText)) {
              library = 'jQuery';
              const vm = bannerText.match(/jQuery\s+(?:v|Version)?\s*([0-9.]+)/i);
              if (vm) version = vm[1];
            } else if (/Bootstrap/i.test(bannerText)) {
              library = 'Bootstrap';
              const vm = bannerText.match(/Bootstrap\s+(?:v|Version)?\s*([0-9.]+)/i);
              if (vm) version = vm[1];
            } else if (/React/i.test(bannerText)) {
              library = 'React';
              const vm = bannerText.match(/React\s+v?([0-9.]+)/i);
              if (vm) version = vm[1];
            }

            return {
              text: bannerText,
              library,
              version
            };
          }
        }
      } catch (e) {}
      return null;
    }

    /**
     * Controlled fetch wrapper with timeouts and range limits
     */
    async _safeFetch(url, signal, timeoutMs = 3500, rangeLimited = false) {
      const headers = { 'Accept': 'text/plain, text/html, application/javascript, */*' };
      if (rangeLimited) {
        headers['Range'] = 'bytes=0-4096'; // First 4KB only
      }

      const timeoutCtrl = new AbortController();
      const timer = setTimeout(() => timeoutCtrl.abort(), timeoutMs);

      // Chain abort signals
      const onAbort = () => timeoutCtrl.abort();
      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true });
      }

      try {
        const resp = await fetch(url, {
          method: 'GET',
          headers: headers,
          signal: timeoutCtrl.signal,
          credentials: 'omit',
          cache: 'no-store'
        });

        clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);

        const text = await resp.text();
        return {
          status: resp.status,
          headers: resp.headers,
          body: text
        };
      } catch (e) {
        clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);
        throw e;
      }
    }
  }

  return {
    DeepScanner
  };
});
