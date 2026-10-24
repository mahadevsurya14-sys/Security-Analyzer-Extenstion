/**
 * Security Analyzer - Security Configuration & Header Analysis Module
 * Non-destructive evaluation of HTTP security headers, transport security,
 * and information disclosure risks.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SecurityAnalyzerSecurityEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Run full non-destructive security analysis.
   * @param {object} scanData - { url, headers, detectedTechnologies, html, scripts }
   * @returns {object} { findings: Array, securityScore: number, grade: string, stats: object }
   */
  function analyzeSecurity(scanData) {
    const findings = [];
    const { url = '', headers = {}, detectedTechnologies = [], scripts = [] } = scanData;

    // Normalize headers
    const norm = {};
    for (const [k, v] of Object.entries(headers || {})) {
      norm[k.toLowerCase()] = String(v).trim();
    }

    const isHttps = url.toLowerCase().startsWith('https://');

    // 1. Transport Security (HTTPS)
    if (!isHttps && url.toLowerCase().startsWith('http://')) {
      findings.push({
        id: 'SEC-TRANSPORT-NO-HTTPS',
        title: 'Unencrypted HTTP Transport In Use',
        severity: 'High',
        category: 'Transport Security',
        description: 'The target website is accessed over plaintext HTTP without TLS encryption.',
        evidence: `URL scheme: ${url.split('://')[0]}://`,
        impact: 'Data transmitted between the client and server is vulnerable to eavesdropping, interception, and man-in-the-middle (MitM) tampering.',
        remediation: 'Migrate the web application to HTTPS and enforce an automatic 301 redirect from HTTP to HTTPS for all routes.',
        confidence: 99
      });
    }

    // 2. Strict-Transport-Security (HSTS)
    const hsts = norm['strict-transport-security'];
    if (isHttps) {
      if (!hsts) {
        findings.push({
          id: 'SEC-HSTS-MISSING',
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          severity: 'Medium',
          category: 'Transport Security',
          description: 'The Strict-Transport-Security header is not sent by the server over HTTPS.',
          evidence: 'Header "Strict-Transport-Security" was not observed in HTTP response headers.',
          impact: 'Users making initial unencrypted requests or following insecure links remain exposed to SSL-stripping and TLS downgrade attacks.',
          remediation: 'Configure the web server to send "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
          confidence: 95
        });
      } else {
        const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        const hasSubDomains = /includeSubDomains/i.test(hsts);
        const hasPreload = /preload/i.test(hsts);

        if (maxAge < 10886400) { // less than 126 days
          findings.push({
            id: 'SEC-HSTS-SHORT-MAXAGE',
            title: 'HSTS max-age Duration Is Too Short',
            severity: 'Low',
            category: 'Transport Security',
            description: `HSTS max-age is set to ${maxAge} seconds (less than the recommended 1 year / 31536000 seconds).`,
            evidence: `Strict-Transport-Security: ${hsts}`,
            impact: 'A short HSTS cache lifetime reduces protection against downgrade attacks for infrequent visitors.',
            remediation: 'Increase the HSTS max-age directive to at least 31536000 seconds (1 year).',
            confidence: 95
          });
        }

        if (!hasSubDomains) {
          findings.push({
            id: 'SEC-HSTS-NO-SUBDOMAINS',
            title: 'HSTS Missing includeSubDomains Directive',
            severity: 'Low',
            category: 'Transport Security',
            description: 'The HSTS policy does not cover subdomains.',
            evidence: `Strict-Transport-Security: ${hsts}`,
            impact: 'Subdomains of this domain may remain susceptible to plaintext interception or SSL-stripping.',
            remediation: 'Append "includeSubDomains" to the Strict-Transport-Security header once all subdomains support HTTPS.',
            confidence: 90
          });
        }
      }
    }

    // 3. Content-Security-Policy (CSP)
    const csp = norm['content-security-policy'];
    const cspReportOnly = norm['content-security-policy-report-only'];

    if (!csp && !cspReportOnly) {
      findings.push({
        id: 'SEC-CSP-MISSING',
        title: 'Missing Content Security Policy (CSP)',
        severity: 'Medium',
        category: 'Content Security',
        description: 'No Content-Security-Policy header was observed in the HTTP response.',
        evidence: 'Headers "Content-Security-Policy" and "Content-Security-Policy-Report-Only" are absent.',
        impact: 'Without CSP, the browser lacks a primary defense-in-depth barrier against Cross-Site Scripting (XSS), data injection, and malicious resource loading.',
        remediation: 'Deploy an enforced Content-Security-Policy restricting script-src, object-src, base-uri, and frame-ancestors using nonces or strict origin whitelists.',
        confidence: 95
      });
    } else {
      const activeCsp = csp || cspReportOnly;

      if (cspReportOnly && !csp) {
        findings.push({
          id: 'SEC-CSP-REPORT-ONLY',
          title: 'Content Security Policy in Report-Only Mode',
          severity: 'Low',
          category: 'Content Security',
          description: 'The server provides CSP via Content-Security-Policy-Report-Only rather than enforcing restrictions.',
          evidence: `Content-Security-Policy-Report-Only: ${activeCsp.slice(0, 100)}...`,
          impact: 'Violations are logged but policy restrictions are not actively enforced in user browsers.',
          remediation: 'Transition the validated report-only policy into an enforced Content-Security-Policy header.',
          confidence: 95
        });
      }

      if (/'unsafe-inline'/i.test(activeCsp) && !/'nonce-|\'sha256-|\'sha384-|\'sha512-/i.test(activeCsp)) {
        findings.push({
          id: 'SEC-CSP-UNSAFE-INLINE',
          title: 'CSP Allows Unsafe Inline Scripts',
          severity: 'Medium',
          category: 'Content Security',
          description: 'The policy includes "\'unsafe-inline\'" in script directives without modern cryptographic nonces or hashes.',
          evidence: `Directives contain 'unsafe-inline' without nonces in: ${activeCsp.slice(0, 120)}...`,
          impact: 'Substantially weakens CSP defense against XSS by allowing arbitrary inline script execution.',
          remediation: 'Refactor inline scripts into external files and adopt CSP Level 3 cryptographic nonces (\'nonce-...\') or hashes.',
          confidence: 90
        });
      }

      if (/'unsafe-eval'/i.test(activeCsp)) {
        findings.push({
          id: 'SEC-CSP-UNSAFE-EVAL',
          title: 'CSP Permits Dynamic Code Evaluation (unsafe-eval)',
          severity: 'Low',
          category: 'Content Security',
          description: 'The policy contains "\'unsafe-eval\'", enabling eval(), Function(), and setTimeout(string).',
          evidence: `Found 'unsafe-eval' in: ${activeCsp.slice(0, 100)}...`,
          impact: 'Enables dynamic string evaluation, increasing the exploitability of potential injection flaws.',
          remediation: 'Eliminate usage of eval() and template libraries requiring dynamic evaluation, then remove \'unsafe-eval\'.',
          confidence: 90
        });
      }

      if (/script-src[^;]*\*/i.test(activeCsp)) {
        findings.push({
          id: 'SEC-CSP-WILDCARD-SRC',
          title: 'CSP Script Directive Uses Wildcard Origin (*)',
          severity: 'Medium',
          category: 'Content Security',
          description: 'The script-src directive permits scripts from any arbitrary remote host (*).',
          evidence: `Wildcard origin found in script directive: ${activeCsp.slice(0, 100)}...`,
          impact: 'An attacker can host malicious payloads on any public domain and load them within this application.',
          remediation: 'Replace wildcard origins with explicit trusted origins, hashes, or nonces.',
          confidence: 90
        });
      }
    }

    // 4. Clickjacking Defense (X-Frame-Options & frame-ancestors)
    const xfo = norm['x-frame-options'];
    const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);

    if (!xfo && !hasFrameAncestors) {
      findings.push({
        id: 'SEC-CLICKJACKING-UNPROTECTED',
        title: 'Missing Clickjacking Protection',
        severity: 'Medium',
        category: 'Frame Security',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors directive is configured.',
        evidence: 'Headers "X-Frame-Options" and CSP directive "frame-ancestors" are both missing.',
        impact: 'The web page can be embedded within an external iframe on malicious websites, enabling clickjacking (UI redressing) attacks.',
        remediation: 'Configure "X-Frame-Options: DENY" (or SAMEORIGIN) and specify "frame-ancestors \'none\'" (or \'self\') in CSP.',
        confidence: 95
      });
    }

    // 5. MIME-Sniffing (X-Content-Type-Options)
    const xcto = norm['x-content-type-options'];
    if (!xcto || xcto.toLowerCase() !== 'nosniff') {
      findings.push({
        id: 'SEC-MIME-SNIFFING',
        title: 'Missing X-Content-Type-Options: nosniff',
        severity: 'Low',
        category: 'Content Security',
        description: 'The server does not prevent browsers from MIME-sniffing response bodies away from the declared Content-Type.',
        evidence: xcto ? `X-Content-Type-Options was "${xcto}" instead of "nosniff"` : 'Header "X-Content-Type-Options" is missing.',
        impact: 'Browsers may interpret non-executable MIME types (e.g. text/plain or image/png) as executable script or HTML if unexpected characters are detected.',
        remediation: 'Configure the web server to send "X-Content-Type-Options: nosniff" on all responses.',
        confidence: 95
      });
    }

    // 6. Referrer-Policy
    const refPolicy = norm['referrer-policy'];
    if (!refPolicy) {
      findings.push({
        id: 'SEC-REFERRER-POLICY-MISSING',
        title: 'Missing Explicit Referrer-Policy',
        severity: 'Low',
        category: 'Information Disclosure',
        description: 'No explicit Referrer-Policy header is configured on the response.',
        evidence: 'Header "Referrer-Policy" is absent.',
        impact: 'Sensitive path components or query parameters in URLs might be inadvertently leaked to external analytics, CDN, or third-party links.',
        remediation: 'Set "Referrer-Policy: strict-origin-when-cross-origin" or "no-referrer" on all responses.',
        confidence: 90
      });
    } else if (/unsafe-url|no-referrer-when-downgrade/i.test(refPolicy)) {
      findings.push({
        id: 'SEC-REFERRER-POLICY-PERMISSIVE',
        title: 'Permissive Referrer-Policy Configured',
        severity: 'Low',
        category: 'Information Disclosure',
        description: `The configured Referrer-Policy (${refPolicy}) permits full URL leakage across origins.`,
        evidence: `Referrer-Policy: ${refPolicy}`,
        impact: 'Full paths and query strings are passed to destination hosts, risking sensitive token or identifier disclosure.',
        remediation: 'Tighten Referrer-Policy to "strict-origin-when-cross-origin".',
        confidence: 90
      });
    }

    // 7. Permissions-Policy
    const permPolicy = norm['permissions-policy'] || norm['feature-policy'];
    if (!permPolicy) {
      findings.push({
        id: 'SEC-PERMISSIONS-POLICY-MISSING',
        title: 'Missing Permissions-Policy Header',
        severity: 'Low',
        category: 'Browser Feature Control',
        description: 'The Permissions-Policy header is not defined to restrict powerful browser hardware APIs.',
        evidence: 'Headers "Permissions-Policy" and "Feature-Policy" are absent.',
        impact: 'Embedded iframes and scripts may request access to sensitive browser features such as geolocation, camera, microphone, or accelerometer without restrictive boundaries.',
        remediation: 'Define a Permissions-Policy restricting unused device capabilities (e.g., "camera=(), microphone=(), geolocation=()").',
        confidence: 85
      });
    }

    // 8. Server & Technology Token Information Disclosure
    const serverHeader = norm['server'];
    if (serverHeader) {
      const hasDetailedVersion = /\d+\.\d+/.test(serverHeader);
      findings.push({
        id: hasDetailedVersion ? 'SEC-INFO-SERVER-VERSION' : 'SEC-INFO-SERVER-TOKEN',
        title: hasDetailedVersion ? 'Web Server Discloses Exact Software Version' : 'Web Server Discloses Server Banner',
        severity: hasDetailedVersion ? 'Low' : 'Informational',
        category: 'Information Disclosure',
        description: hasDetailedVersion
          ? `The Server header reveals specific software and version details (${serverHeader}).`
          : `The Server header reveals the underlying server software family (${serverHeader}).`,
        evidence: `Server: ${serverHeader}`,
        impact: 'Public disclosure of precise server software and patch levels assists attackers during reconnaissance in tailoring exploits to specific CVEs.',
        remediation: 'Configure the web server to suppress or tokenize the Server header (e.g. "ServerTokens Prod" in Apache or "server_tokens off;" in Nginx).',
        confidence: 95
      });
    }

    const poweredBy = norm['x-powered-by'];
    if (poweredBy) {
      findings.push({
        id: 'SEC-INFO-X-POWERED-BY',
        title: 'X-Powered-By Header Discloses Backend Runtime',
        severity: 'Low',
        category: 'Information Disclosure',
        description: `The X-Powered-By header exposes the backend technology stack (${poweredBy}).`,
        evidence: `X-Powered-By: ${poweredBy}`,
        impact: 'Exposes backend implementation details and version numbers to unauthenticated observers.',
        remediation: 'Disable the X-Powered-By header in application or web server configurations (e.g. "expose_php = Off" in php.ini, "app.disable(\'x-powered-by\')" in Express).',
        confidence: 95
      });
    }

    const aspNetVer = norm['x-aspnet-version'] || norm['x-aspnetmvc-version'];
    if (aspNetVer) {
      findings.push({
        id: 'SEC-INFO-ASPNET-VERSION',
        title: 'ASP.NET Version Header Exposed',
        severity: 'Low',
        category: 'Information Disclosure',
        description: `The web application exposes internal ASP.NET framework version details.`,
        evidence: `Header: ${aspNetVer}`,
        impact: 'Reveals internal Microsoft .NET framework versioning.',
        remediation: 'Set <httpRuntime enableVersionHeader="false" /> in web.config.',
        confidence: 95
      });
    }

    // 9. Outdated Frontend Libraries
    for (const tech of detectedTechnologies) {
      if (tech.id === 'jquery' && tech.version) {
        const v = tech.version;
        // Check if jQuery is 1.x or 2.x or 3.0-3.4
        if (/^[0-2]\./.test(v) || /^3\.[0-4]\./.test(v)) {
          findings.push({
            id: 'SEC-LIB-OUTDATED-JQUERY',
            title: `Outdated jQuery Version (${v}) In Use`,
            severity: 'Medium',
            category: 'Outdated Components',
            description: `The page loads jQuery version ${v}, which contains known historical security advisories (e.g. XSS in $.htmlPrefilter).`,
            evidence: `Detected jQuery version: ${v} (status: ${tech.versionStatus})`,
            impact: 'Potential exposure to cross-site scripting flaws in legacy DOM manipulation functions when parsing untrusted HTML.',
            remediation: 'Upgrade to the current stable release of jQuery (>= 3.7.1) and audit DOM calls.',
            confidence: tech.confidence || 85
          });
        }
      }

      if (tech.id === 'angular' && tech.version && /^1\./.test(tech.version)) {
        findings.push({
          id: 'SEC-LIB-EOL-ANGULARJS',
          title: `End-of-Life AngularJS 1.x (${tech.version}) Detected`,
          severity: 'Medium',
          category: 'Outdated Components',
          description: 'AngularJS (1.x branch) reached official End-of-Life (EOL) in January 2022 and no longer receives security patches.',
          evidence: `Angular version: ${tech.version}`,
          impact: 'Unpatched security flaws will remain permanently unaddressed by upstream maintainers.',
          remediation: 'Migrate to modern Angular (v16+) or another actively maintained frontend framework.',
          confidence: tech.confidence || 90
        });
      }
    }

    // 10. Mixed Content Checks (if HTTPS)
    if (isHttps && Array.isArray(scripts)) {
      const insecureScripts = scripts.filter(s => typeof s === 'string' && s.toLowerCase().startsWith('http://'));
      if (insecureScripts.length > 0) {
        findings.push({
          id: 'SEC-MIXED-CONTENT-SCRIPTS',
          title: 'Active Mixed Content Detected',
          severity: 'High',
          category: 'Transport Security',
          description: `The HTTPS page includes script resources fetched over unencrypted plaintext HTTP (${insecureScripts.length} script(s)).`,
          evidence: `Insecure script sample: ${insecureScripts[0]}`,
          impact: 'Plaintext script assets can be intercepted and modified by an active network adversary to execute arbitrary code in users\' sessions.',
          remediation: 'Update script URLs to use https:// or relative paths, and set "upgrade-insecure-requests" in CSP.',
          confidence: 95
        });
      }
    }

    // Calculate Security Score & Grade
    let score = 100;
    const stats = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };

    for (const f of findings) {
      if (stats[f.severity] !== undefined) {
        stats[f.severity]++;
      }
      switch (f.severity) {
        case 'Critical': score -= 25; break;
        case 'High': score -= 15; break;
        case 'Medium': score -= 8; break;
        case 'Low': score -= 3; break;
        case 'Informational': score -= 0; break;
      }
    }
    score = Math.max(0, Math.min(100, score));

    let grade = 'A';
    if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 55) grade = 'D';
    else grade = 'F';

    return {
      findings,
      securityScore: score,
      grade,
      stats,
      analyzedAt: new Date().toISOString()
    };
  }

  return {
    analyzeSecurity
  };
});
