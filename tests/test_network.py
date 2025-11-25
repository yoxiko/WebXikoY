import pytest
import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.network.port_scanner import PortScanner
from scanners.network.service_detector import ServiceDetector
from core.config import ConfigManager

class TestNetworkScanner:
    def setup_method(self):
        self.config = ConfigManager()
        self.port_scanner = PortScanner(self.config)
        self.service_detector = ServiceDetector(self.config)

    @pytest.mark.asyncio
    async def test_port_scan_localhost(self):
        open_ports = await self.port_scanner.scapy_scan("127.0.0.1")
        assert isinstance(open_ports, list)

    @pytest.mark.asyncio
    async def test_service_detection(self):
        service_info = await self.service_detector.detect_service("127.0.0.1", 80)
        assert 'port' in service_info
        assert 'name' in service_info