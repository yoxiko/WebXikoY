from fastapi import APIRouter, HTTPException
from typing import List
import asyncio

router = APIRouter()

@router.get("/health")
async def health_check():
    return {"status": "healthy"}

@router.post("/scan/stop/{scan_id}")
async def stop_scan(scan_id: str):
    return {"message": "Scan stopping not implemented yet"}

@router.get("/scans")
async def list_scans():
    from api.main import scan_jobs
    return {"scans": list(scan_jobs.keys())}