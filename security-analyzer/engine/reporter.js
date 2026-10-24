/**
 * Security Analyzer - Report Generation Module
 * Exports audit findings and technology detections in JSON and CSV formats.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SecurityAnalyzerReporter = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const DISCLAIMER = 'This automated security analysis is provided for educational and diagnostic assessment purposes only. Findings reflect publicly observable headers, scripts, and heuristic version patterns. This report does not constitute a comprehensive penetration test, formal security audit, or guarantee of security posture.';

  /**
   * Generates a comprehensive JSON report.
   */
  function generateJsonReport(scanData) {
    const {
      url = '',
      timestamp = new Date().toISOString(),
      securityScore = 100,
      grade = 'A',
      technologies = [],
      securityFindings = [],
      vulnerabilities = [],
      deepScanResults = null
    } = scanData;

    return {
      reportMetadata: {
        product: 'Security Analyzer',
        version: '1.0.0',
        timestamp: timestamp,
        targetUrl: url,
        disclaimer: DISCLAIMER
      },
      executiveSummary: {
        targetUrl: url,
        securityScore: securityScore,
        securityGrade: grade,
        technologiesIdentified: technologies.length,
        securityFindingsCount: securityFindings.length,
        potentialCveMatches: vulnerabilities.length
      },
      detectedTechnologies: (technologies || []).map(t => ({
        name: t.name,
        category: t.category,
        version: t.version || 'Unknown',
        versionStatus: t.versionStatus,
        confidence: t.confidence,
        detectionMethod: t.detectionMethod,
        evidence: (t.evidence || []).map(e => e.detail),
        limitations: t.uncertainties || []
      })),
      securityFindings: (securityFindings || []).map(f => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        confidence: f.confidence,
        description: f.description,
        evidence: f.evidence,
        impact: f.impact,
        remediation: f.remediation
      })),
      vulnerabilityIntelligence: (vulnerabilities || []).map(v => ({
        cveId: v.cveId,
        technology: v.techName,
        detectedVersion: v.detectedVersion,
        cvssScore: v.cvssScore,
        severity: v.severity,
        title: v.title,
        remediation: v.remediation,
        reference: v.reference,
        statusNote: v.disclaimer
      })),
      deepScan: deepScanResults ? {
        completed: deepScanResults.completed,
        securityTxtPresent: !!(deepScanResults.securityTxt && deepScanResults.securityTxt.found),
        robotsTxtPresent: !!(deepScanResults.robotsTxt && deepScanResults.robotsTxt.found),
        sensitiveDisallowedPaths: deepScanResults.robotsTxt?.sensitivePaths || [],
        scriptBannersAudited: deepScanResults.scriptBanners?.length || 0
      } : null
    };
  }

  /**
   * Helper to escape CSV values
   */
  function csvEscape(val) {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  }

  /**
   * Generates a flat CSV report
   */
  function generateCsvReport(scanData) {
    const {
      url = '',
      timestamp = new Date().toISOString(),
      securityScore = 100,
      grade = 'A',
      technologies = [],
      securityFindings = [],
      vulnerabilities = []
    } = scanData;

    const lines = [];

    // Header info
    lines.push(['# Security Analyzer Audit Report', '', '', '', '', ''].map(csvEscape).join(','));
    lines.push(['Target URL', url, 'Generated At', timestamp, 'Security Score', `${securityScore}/100 (${grade})`].map(csvEscape).join(','));
    lines.push(['Disclaimer', DISCLAIMER, '', '', '', ''].map(csvEscape).join(','));
    lines.push(['', '', '', '', '', ''].map(csvEscape).join(','));

    // Section 1: Detected Technologies
    lines.push(['[SECTION: DETECTED TECHNOLOGIES]', '', '', '', '', ''].map(csvEscape).join(','));
    lines.push(['Technology', 'Category', 'Version', 'Version Status', 'Confidence', 'Detection Method'].map(csvEscape).join(','));
    for (const t of (technologies || [])) {
      lines.push([
        t.name,
        t.category,
        t.version || 'Unknown',
        t.versionStatus,
        `${t.confidence}%`,
        t.detectionMethod
      ].map(csvEscape).join(','));
    }

    lines.push(['', '', '', '', '', ''].map(csvEscape).join(','));

    // Section 2: Security Findings
    lines.push(['[SECTION: SECURITY FINDINGS]', '', '', '', '', ''].map(csvEscape).join(','));
    lines.push(['Finding ID', 'Title', 'Severity', 'Category', 'Confidence', 'Remediation'].map(csvEscape).join(','));
    for (const f of (securityFindings || [])) {
      lines.push([
        f.id,
        f.title,
        f.severity,
        f.category,
        `${f.confidence}%`,
        f.remediation
      ].map(csvEscape).join(','));
    }

    lines.push(['', '', '', '', '', ''].map(csvEscape).join(','));

    // Section 3: Vulnerability Intelligence
    lines.push(['[SECTION: VULNERABILITY INTELLIGENCE (CVE MATCHES)]', '', '', '', '', ''].map(csvEscape).join(','));
    lines.push(['CVE Identifier', 'Technology', 'Version', 'CVSS Score', 'Severity', 'Remediation Advisory'].map(csvEscape).join(','));
    for (const v of (vulnerabilities || [])) {
      lines.push([
        v.cveId,
        v.techName,
        v.detectedVersion,
        v.cvssScore,
        v.severity,
        v.remediation
      ].map(csvEscape).join(','));
    }

    return lines.join('\r\n');
  }

  /**
   * Browser helper to download a file
   */
  function triggerDownload(content, filename, mimeType) {
    if (typeof document === 'undefined') return;
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  return {
    generateJsonReport,
    generateCsvReport,
    triggerDownload,
    DISCLAIMER
  };
});
