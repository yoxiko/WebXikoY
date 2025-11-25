import pytest
from scanners.web.vulnerability import WebVulnerabilityScanner
from core.config import ConfigManager

class TestWebScanner:
    def setup_method(self):
        self.config = ConfigManager()

    @pytest.mark.asyncio
    async def test_xss_detection(self):
        import aiohttp
        async with aiohttp.ClientSession() as session:
            scanner = WebVulnerabilityScanner(self.config, session)
            vulnerabilities = await scanner.scan_target("http://testphp.vulnweb.com")
            assert isinstance(vulnerabilities, list)