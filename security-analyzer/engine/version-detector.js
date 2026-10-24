/**
 * Security Analyzer - Version Detection Engine
 * Classifies software versions as Exact, Inferred, Partial, or Unknown
 * based on the reliability of the source signal.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SecurityAnalyzerVersionDetector = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const SEMVER_FULL = /^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.+_-]+)?$/;
  const SEMVER_PARTIAL = /^\d+(\.\d+)?$/;

  /**
   * Sanitizes and cleans a raw version string.
   */
  function cleanVersion(raw) {
    if (!raw || typeof raw !== 'string') return null;
    let v = raw.trim();
    // Strip leading 'v' or 'v.'
    v = v.replace(/^v\.?/i, '');
    // Strip trailing query artifacts or punctuation
    v = v.replace(/[\?#;&].*$/, '').replace(/[;,)]+$/, '');
    return v.trim() || null;
  }

  /**
   * Classifies a detected version.
   * @param {string} rawVersion - The raw version found
   * @param {string} detectionMethod - 'runtime_global' | 'meta_generator' | 'http_header' | 'script_url' | 'dom_attribute' | 'banner'
   * @param {string} source - Description of evidence
   * @returns {object} { version, status, confidence, limitation }
   */
  function classify(rawVersion, detectionMethod, source) {
    const cleaned = cleanVersion(rawVersion);

    if (!cleaned) {
      return {
        version: null,
        status: 'Unknown',
        confidence: 0,
        limitation: 'No reliable version indicators were exposed.'
      };
    }

    // Check if semver is exact (x.y.z)
    const isFullSemver = /^\d+\.\d+\.\d+/.test(cleaned);
    const isMajorMinor = /^\d+\.\d+$/.test(cleaned);
    const isMajorOnly = /^\d+$/.test(cleaned);

    switch (detectionMethod) {
      case 'runtime_global':
        return {
          version: cleaned,
          status: isFullSemver ? 'Exact' : 'Inferred',
          confidence: isFullSemver ? 95 : 85,
          limitation: isFullSemver
            ? null
            : 'Runtime object exposed partial version string without patch level.'
        };

      case 'http_header':
        return {
          version: cleaned,
          status: isFullSemver ? 'Exact' : (isMajorMinor ? 'Partial' : 'Inferred'),
          confidence: isFullSemver ? 95 : 80,
          limitation: isFullSemver
            ? null
            : 'HTTP header revealed major/minor release without exact patch level.'
        };

      case 'meta_generator':
        return {
          version: cleaned,
          status: isFullSemver ? 'Exact' : 'Inferred',
          confidence: 90,
          limitation: 'Derived from public HTML generator meta tag; may be masked by security plugins.'
        };

      case 'dom_attribute':
        return {
          version: cleaned,
          status: isFullSemver ? 'Exact' : 'Inferred',
          confidence: 90,
          limitation: null
        };

      case 'script_banner':
        return {
          version: cleaned,
          status: isFullSemver ? 'Exact' : 'Inferred',
          confidence: 90,
          limitation: 'Extracted from comment banner inside script payload.'
        };

      case 'script_url':
        return {
          version: cleaned,
          status: isFullSemver ? 'Inferred' : 'Partial',
          confidence: 75,
          limitation: 'Inferred from script asset URL/query string; actual runtime payload may differ.'
        };

      default:
        return {
          version: cleaned,
          status: isFullSemver ? 'Inferred' : 'Partial',
          confidence: 70,
          limitation: 'Inferred from heuristic fingerprinting.'
        };
    }
  }

  /**
   * Extract version from text using provided regex pattern
   */
  function extractWithPattern(text, regexPattern) {
    if (!text || !regexPattern) return null;
    try {
      const rx = typeof regexPattern === 'string' ? new RegExp(regexPattern, 'i') : regexPattern;
      const match = text.match(rx);
      if (match) {
        // Return first capture group or full match
        return match[1] || match[0];
      }
    } catch (e) {
      // Regex parse fail
    }
    return null;
  }

  return {
    cleanVersion,
    classify,
    extractWithPattern
  };
});
