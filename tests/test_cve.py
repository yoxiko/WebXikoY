import pytest
from cve.manager import CVEManager
from core.config import ConfigManager

class TestCVEManager:
    def setup_method(self):
        self.config = ConfigManager()
        self.cve_manager = CVEManager(self.config)

    def test_cve_lookup(self):
        cves = self.cve_manager.get_cves_for_service("apache", "2.4.49")
        assert isinstance(cves, list)

    def test_cve_details(self):
        details = self.cve_manager.get_cve_details("CVE-2021-41773")
        assert isinstance(details, dict)