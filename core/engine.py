import asyncio
import aiohttp
from typing import List, Dict, Any
from dataclasses import dataclass
from .config import ConfigManager
from .security import SecurityManager

@dataclass
class ScanResult:
    target: str
    vulnerabilities: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    cves: List[Dict[str, Any]]

class ScanEngine:
    def __init__(self):
        self.config = ConfigManager()
        self.security = SecurityManager(self.config)
        self.active_scans = {}
    
    async def initialize(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.scanner.timeout)
        )
    
    async def shutdown(self):
        await self.session.close()
    
    async def scan_network(self, targets: List[str], profile: str = "default") -> List[ScanResult]:
        results = []
        
        async with asyncio.Semaphore(self.config.scanner.max_hosts):
            tasks = [self._scan_single_target(target, profile) for target in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, ScanResult)]
    
    async def _scan_single_target(self, target: str, profile: str) -> ScanResult:
        if not await self.security.rate_limit_check(target):
            raise RuntimeError(f"Rate limit exceeded for {target}")
        
        if not self.security.verify_scope(target, profile):
            raise SecurityError(f"Target {target} not in scope")
        
        async with self.security.isolated_execution():
            network_results = await self._run_network_scan(target)
            web_results = await self._run_web_scan(target)
            cve_results = await self._analyze_cves(target, network_results)
            
            return ScanResult(
                target=target,
                vulnerabilities=web_results,
                services=network_results,
                cves=cve_results
            )
    
    async def _run_network_scan(self, target: str) -> List[Dict[str, Any]]:
        from scanners.network.port_scanner import PortScanner
        from scanners.network.service_detector import ServiceDetector
        from scanners.network.tls_analyzer import TLSAnalyzer
        
        scanner = PortScanner(self.config)
        detector = ServiceDetector(self.config)
        tls_analyzer = TLSAnalyzer(self.config)
        
        open_ports = await scanner.scapy_scan(target)
        services = []
        
        for port in open_ports:
            service = await detector.detect_service(target, port)
            if service.get('tls_enabled', False):
                service['tls_info'] = await tls_analyzer.analyze_tls(target, port)
            services.append(service)
        
        return services
    
    async def _run_web_scan(self, target: str) -> List[Dict[str, Any]]:
        from scanners.web.vulnerability import WebVulnerabilityScanner
        
        scanner = WebVulnerabilityScanner(self.config, self.session)
        return await scanner.scan_target(target)
    
    async def _analyze_cves(self, target: str, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        from cve.manager import CVEManager
        
        cve_manager = CVEManager(self.config)
        cves = []
        
        for service in services:
            service_cves = await cve_manager.get_cves_for_service(
                service['name'],
                service['version']
            )
            cves.extend(service_cves)
        
        return cves

class SecurityError(Exception):
    pass