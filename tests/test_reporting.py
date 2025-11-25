import pytest
from reporting.generator import ReportGenerator
from core.config import ConfigManager

class TestReporting:
    def setup_method(self):
        self.config = ConfigManager()
        self.reporter = ReportGenerator(self.config)

    @pytest.mark.asyncio
    async def test_html_report(self):
        sample_data = {
            'services': [{'port': 80, 'name': 'http', 'version': '1.0'}],
            'vulnerabilities': [],
            'cves': {'critical': [], 'high': [], 'medium': [], 'low': [], 'total': 0}
        }
        report = await self.reporter.generate_html_report(sample_data, "test.com")
        assert isinstance(report, str)
        assert "WebXikoY" in report

    @pytest.mark.asyncio
    async def test_json_report(self):
        sample_data = {
            'services': [{'port': 80, 'name': 'http', 'version': '1.0'}],
            'vulnerabilities': [],
            'cves': {'critical': [], 'high': [], 'medium': [], 'low': [], 'total': 0}
        }
        report = await self.reporter.generate_json_report(sample_data, "test.com")
        assert isinstance(report, str)
        assert "metadata" in report