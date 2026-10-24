"""
Security Analyzer - FastAPI Backend Service
Provides SSRF-protected passive network probing and enriched vulnerability intelligence.
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
import time
import httpx

from .ssrf_guard import validate_target_url, SSRFValidationError

app = FastAPI(
    title="Security Analyzer API",
    description="Lightweight backend for SSRF-protected target analysis and CVE enrichment.",
    version="1.0.0"
)

# Allow Chrome Extension origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target HTTP or HTTPS URL to audit")


class TechItem(BaseModel):
    name: str
    version: Optional[str] = None
    category: Optional[str] = None


class VulnEnrichRequest(BaseModel):
    technologies: List[TechItem]


@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "service": "Security Analyzer API",
        "version": "1.0.0",
        "features": {
            "ssrf_protection": True,
            "cve_enrichment": True,
            "passive_probing": True
        }
    }


@app.post("/api/scan")
async def scan_target(req: ScanRequest):
    """
    Performs safe, SSRF-protected passive header and certificate inspection.
    """
    target = req.target_url.strip()

    # 1. SSRF Safety Gate
    try:
        is_safe, resolved_ip, msg = validate_target_url(target)
    except SSRFValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Safety Policy Violation: {str(e)}"
        )

    # 2. Perform safe, non-destructive probe with strict timeout
    start_time = time.time()
    headers_dict: Dict[str, str] = {}
    status_code: int = 0

    try:
        async with httpx.AsyncClient(verify=True, timeout=6.0, follow_redirects=True) as client:
            resp = await client.head(target, headers={"User-Agent": "SecurityAnalyzer/1.0 (Defensive Audit)"})
            status_code = resp.status_code
            for k, v in resp.headers.items():
                headers_dict[k.lower()] = v
    except Exception:
        # Some servers reject HEAD; retry with minimal GET
        try:
            async with httpx.AsyncClient(verify=True, timeout=6.0, follow_redirects=True) as client:
                resp = await client.get(
                    target,
                    headers={
                        "User-Agent": "SecurityAnalyzer/1.0 (Defensive Audit)",
                        "Range": "bytes=0-1024"
                    }
                )
                status_code = resp.status_code
                for k, v in resp.headers.items():
                    headers_dict[k.lower()] = v
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Target probe failed: {str(e)}"
            )

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "target_url": target,
        "resolved_ip": resolved_ip,
        "status_code": status_code,
        "latency_ms": elapsed_ms,
        "headers": headers_dict,
        "ssrf_verification": "Passed"
    }


@app.post("/api/vulns/enrich")
async def enrich_vulnerabilities(req: VulnEnrichRequest):
    """
    Enriches detected components with additional vulnerability advisory details.
    """
    results: List[Dict[str, Any]] = []

    for t in req.technologies:
        if not t.version:
            continue

        # Sample query to OSV API (gracefully handled)
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                osv_resp = await client.post(
                    "https://api.osv.dev/v1/query",
                    json={"package": {"name": t.name.lower()}, "version": t.version}
                )
                if osv_resp.status_code == 200:
                    data = osv_resp.json()
                    vulns = data.get("vulns", [])
                    for v in vulns[:3]:
                        results.append({
                            "cve_id": v.get("id"),
                            "technology": t.name,
                            "version": t.version,
                            "summary": v.get("summary", "Advisory reported"),
                            "source": "OSV.dev Community Feed"
                        })
        except Exception:
            # Degrade gracefully if external API is unreachable or rate limited
            pass

    return {
        "enriched_count": len(results),
        "advisories": results,
        "source": "Security Analyzer Vulnerability Intelligence"
    }
