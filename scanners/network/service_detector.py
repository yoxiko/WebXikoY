import asyncio
import aiohttp
from typing import Dict, Any

class ServiceDetector:
    def __init__(self, config):
        self.config = config
        self.service_signatures = {
            21: "ftp",
            22: "ssh", 
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            443: "https",
            3389: "rdp"
        }

    async def detect_service(self, target: str, port: int) -> Dict[str, Any]:
        service_info = {
            'port': port,
            'name': 'unknown',
            'version': 'unknown',
            'banner': ''
        }
        
        service_name = self.service_signatures.get(port, 'unknown')
        service_info['name'] = service_name
        
        banner = await self._grab_banner(target, port)
        if banner:
            service_info['banner'] = banner
            service_info['version'] = self._parse_version(banner, service_name)
        
        service_info['tls_enabled'] = await self._check_tls(target, port)
        
        return service_info

    async def _grab_banner(self, target: str, port: int) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.config.scanner.timeout
            )
            
            await asyncio.sleep(0.5)
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    async def _check_tls(self, target: str, port: int) -> bool:
        try:
            import ssl
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ssl.create_default_context()),
                timeout=self.config.scanner.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def _parse_version(self, banner: str, service: str) -> str:
        if 'SSH' in banner:
            return banner.split('-')[1].split()[0] if '-' in banner else 'unknown'
        elif 'Apache' in banner:
            return banner.split('/')[1].split()[0] if '/' in banner else 'unknown'
        elif 'nginx' in banner:
            return banner.split('/')[1].split()[0] if '/' in banner else 'unknown'
        return 'unknown'