from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import uuid
from core.engine import ScanEngine
from core.config import ConfigManager

app = FastAPI(title="WebXikoY API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

config = ConfigManager()
engine = ScanEngine()
scan_jobs = {}

@app.on_event("startup")
async def startup_event():
    await engine.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    await engine.shutdown()

@app.post("/scan")
async def start_scan(targets: List[str], profile: str = "default", background_tasks: BackgroundTasks = None):
    scan_id = str(uuid.uuid4())
    
    async def run_scan():
        try:
            results = await engine.scan_network(targets, profile)
            scan_jobs[scan_id] = {
                'status': 'completed',
                'results': [r.__dict__ for r in results]
            }
        except Exception as e:
            scan_jobs[scan_id] = {
                'status': 'failed',
                'error': str(e)
            }
    
    background_tasks.add_task(run_scan)
    scan_jobs[scan_id] = {'status': 'running'}
    
    return {"scan_id": scan_id, "status": "started"}

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id not in scan_jobs:
        return {"error": "Scan not found"}
    
    return scan_jobs[scan_id]

@app.get("/cve/{cve_id}")
async def get_cve_info(cve_id: str):
    details = engine._analyze_cves.__self__.cve_manager.get_cve_details(cve_id)
    if not details:
        return {"error": "CVE not found"}
    return details

@app.post("/cve/search")
async def search_cves(product: str, version: str):
    cves = engine._analyze_cves.__self__.cve_manager.get_cves_for_service(product, version)
    return {"cves": cves}

@app.get("/stats")
async def get_stats():
    stats = engine._analyze_cves.__self__.cve_manager.get_statistics()
    return stats

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)