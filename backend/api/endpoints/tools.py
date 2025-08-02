"""
Security tools integration endpoints.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
import asyncio
import time
import uuid
from datetime import datetime
import logging

from backend.config import settings
from backend.api.models.schemas import ToolRequest, ToolResponse
from backend.api.endpoints.auth import get_current_user
from backend.tools.scanning.nmap_scanner import NmapScanner
from backend.tools.scanning.nuclei_scanner import NucleiScanner
from backend.tools.exploitation.payload_generator import PayloadGenerator
from backend.tools.reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize tools
nmap_scanner = NmapScanner()
nuclei_scanner = NucleiScanner()
payload_generator = PayloadGenerator()
report_generator = ReportGenerator()


@router.post("/scan/nmap", response_model=ToolResponse)
async def nmap_scan(
    request: ToolRequest,
    current_user: dict = Depends(get_current_user)
):
    """Execute Nmap scan."""
    start_time = time.time()
    
    try:
        logger.info(f"Nmap scan requested by {current_user['username']} for target: {request.target}")
        
        # Validate target
        if not _is_valid_target(request.target):
            raise HTTPException(status_code=400, detail="Invalid target format")
        
        # Execute scan
        result = await nmap_scanner.scan(
            target=request.target,
            options=request.options or {}
        )
        
        execution_time = time.time() - start_time
        
        return ToolResponse(
            tool="nmap",
            target=request.target,
            status="completed",
            output=result,
            execution_time=execution_time,
            timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Nmap scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/nuclei", response_model=ToolResponse)
async def nuclei_scan(
    request: ToolRequest,
    current_user: dict = Depends(get_current_user)
):
    """Execute Nuclei vulnerability scan."""
    start_time = time.time()
    
    try:
        logger.info(f"Nuclei scan requested by {current_user['username']} for target: {request.target}")
        
        # Validate target
        if not _is_valid_target(request.target):
            raise HTTPException(status_code=400, detail="Invalid target format")
        
        # Execute scan
        result = await nuclei_scanner.scan(
            target=request.target,
            templates=request.options.get("templates", []) if request.options else []
        )
        
        execution_time = time.time() - start_time
        
        return ToolResponse(
            tool="nuclei",
            target=request.target,
            status="completed",
            output=result,
            execution_time=execution_time,
            timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Nuclei scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/payloads/generate")
async def generate_payload(
    payload_type: str,
    target_language: str = "python",
    current_user: dict = Depends(get_current_user)
):
    """Generate security testing payloads."""
    try:
        logger.info(f"Payload generation requested by {current_user['username']}: {payload_type}")
        
        payload = payload_generator.generate(
            payload_type=payload_type,
            language=target_language
        )
        
        return {
            "payload_type": payload_type,
            "language": target_language,
            "payload": payload,
            "description": payload_generator.get_description(payload_type),
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Payload generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reports/generate")
async def generate_report(
    background_tasks: BackgroundTasks,
    scan_results: dict,
    report_format: str = "pdf",
    current_user: dict = Depends(get_current_user)
):
    """Generate security assessment report."""
    try:
        report_id = str(uuid.uuid4())
        
        logger.info(f"Report generation requested by {current_user['username']}: {report_id}")
        
        # Generate report in background
        background_tasks.add_task(
            _generate_report_background,
            report_id,
            scan_results,
            report_format,
            current_user['username']
        )
        
        return {
            "report_id": report_id,
            "status": "generating",
            "format": report_format,
            "message": "Report generation started"
        }
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}/status")
async def get_report_status(
    report_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get report generation status."""
    # Mock implementation - replace with real database query
    return {
        "report_id": report_id,
        "status": "completed",
        "download_url": f"/api/v1/tools/reports/{report_id}/download"
    }


@router.get("/status")
async def tools_status(current_user: dict = Depends(get_current_user)):
    """Get security tools status."""
    return {
        "nmap_available": nmap_scanner.is_available(),
        "nuclei_available": nuclei_scanner.is_available(),
        "tools_timeout": settings.tools_timeout,
        "supported_scan_types": ["tcp", "udp", "syn", "ack"],
        "available_payloads": payload_generator.list_payload_types()
    }


def _is_valid_target(target: str) -> bool:
    """Validate scan target."""
    # Basic validation - enhance with proper IP/domain validation
    if not target or len(target) > 255:
        return False
    
    # Block internal/localhost addresses for security
    blocked_targets = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    for blocked in blocked_targets:
        if blocked in target.lower():
            return False
    
    return True


async def _generate_report_background(report_id: str, scan_results: dict, format: str, username: str):
    """Background task for report generation."""
    try:
        logger.info(f"Starting background report generation: {report_id}")
        
        report_path = await report_generator.generate(
            report_id=report_id,
            scan_results=scan_results,
            format=format
        )
        
        logger.info(f"Report generated successfully: {report_id}")
        
    except Exception as e:
        logger.error(f"Background report generation failed: {e}")