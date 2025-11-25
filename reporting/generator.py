import json
import pdfkit
from datetime import datetime
from typing import List, Dict, Any
import os

class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.templates_dir = "reporting/templates"

    async def generate_html_report(self, scan_results: Dict[str, Any], target: str) -> str:
        template_path = os.path.join(self.templates_dir, "report.html")
        css_path = os.path.join(self.templates_dir, "style.css")
        
        with open(template_path, 'r') as f:
            html_template = f.read()
        
        with open(css_path, 'r') as f:
            css_content = f.read()
        
        cve_stats = self._calculate_cve_stats(scan_results.get('cves', {}))
        web_vulns = scan_results.get('vulnerabilities', [])
        
        context = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': target,
            'stats': cve_stats,
            'critical_vulns': scan_results.get('cves', {}).get('critical', []),
            'high_vulns': scan_results.get('cves', {}).get('high', []),
            'web_vulns': web_vulns,
            'recommendations': self._generate_recommendations(scan_results),
            'css_content': css_content
        }
        
        return self._render_template(html_template, context)

    async def generate_pdf_report(self, scan_results: Dict[str, Any], target: str) -> bytes:
        html_content = await self.generate_html_report(scan_results, target)
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
        }
        
        return pdfkit.from_string(html_content, False, options=options)

    async def generate_json_report(self, scan_results: Dict[str, Any], target: str) -> str:
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'target': target,
                'scanner': 'WebXikoY',
                'version': '1.0'
            },
            'summary': self._calculate_cve_stats(scan_results.get('cves', {})),
            'network_services': scan_results.get('services', []),
            'cve_vulnerabilities': scan_results.get('cves', {}),
            'web_vulnerabilities': scan_results.get('vulnerabilities', []),
            'recommendations': self._generate_recommendations(scan_results)
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)

    def _calculate_cve_stats(self, cve_results: Dict[str, Any]) -> Dict[str, int]:
        return {
            'critical': len(cve_results.get('critical', [])),
            'high': len(cve_results.get('high', [])),
            'medium': len(cve_results.get('medium', [])),
            'low': len(cve_results.get('low', [])),
            'total': cve_results.get('total', 0)
        }

    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        recommendations = []
        
        cves = scan_results.get('cves', {})
        web_vulns = scan_results.get('vulnerabilities', [])
        
        if cves.get('critical'):
            recommendations.append("Apply critical security patches immediately for identified CVE vulnerabilities")
        
        if cves.get('high'):
            recommendations.append("Update software to latest versions to address high severity CVEs")
        
        if any(vuln['type'] == 'SQL Injection' for vuln in web_vulns):
            recommendations.append("Implement parameterized queries and input validation to prevent SQL injection")
        
        if any(vuln['type'] == 'XSS' for vuln in web_vulns):
            recommendations.append("Implement output encoding and Content Security Policy to prevent XSS")
        
        if any(vuln['type'] == 'Command Injection' for vuln in web_vulns):
            recommendations.append("Use safe API functions and input validation to prevent command injection")
        
        services = scan_results.get('services', [])
        for service in services:
            if service.get('tls_enabled') is False and service['port'] in [80, 443]:
                recommendations.append(f"Enable TLS/SSL on service {service['name']} port {service['port']}")
        
        if not recommendations:
            recommendations.append("No critical issues found. Maintain current security practices and monitoring.")
        
        return recommendations

    def _render_template(self, template: str, context: Dict[str, Any]) -> str:
        for key, value in context.items():
            placeholder = "{{ " + key + " }}"
            template = template.replace(placeholder, str(value))
        return template

    async def export_to_ticket(self, scan_results: Dict[str, Any], target: str, system: str = "jira") -> Dict[str, Any]:
        json_report = await self.generate_json_report(scan_results, target)
        data = json.loads(json_report)
        
        if system == "jira":
            return self._format_jira_ticket(data)
        elif system == "servicenow":
            return self._format_servicenow_ticket(data)
        else:
            return data

    def _format_jira_ticket(self, data: Dict[str, Any]) -> Dict[str, Any]:
        critical_count = data['summary']['critical']
        high_count = data['summary']['high']
        
        return {
            'fields': {
                'project': {'key': 'SEC'},
                'summary': f'Security Scan Results: {critical_count} Critical, {high_count} High vulnerabilities',
                'description': self._create_jira_description(data),
                'issuetype': {'name': 'Security Issue'},
                'priority': {'name': 'Critical' if critical_count > 0 else 'High' if high_count > 0 else 'Medium'}
            }
        }

    def _format_servicenow_ticket(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'short_description': f'Security vulnerabilities found in scan',
            'description': json.dumps(data, indent=2),
            'urgency': '1' if data['summary']['critical'] > 0 else '2',
            'category': 'Security'
        }

    def _create_jira_description(self, data: Dict[str, Any]) -> str:
        desc = f"Security scan completed for {data['metadata']['target']}\n\n"
        desc += f"*Critical:* {data['summary']['critical']} | *High:* {data['summary']['high']} | "
        desc += f"*Medium:* {data['summary']['medium']} | *Low:* {data['summary']['low']}\n\n"
        
        if data['cve_vulnerabilities'].get('critical'):
            desc += "Critical CVEs found:\n"
            for cve in data['cve_vulnerabilities']['critical'][:3]:
                desc += f"* {cve['id']} - {cve['service']}\n"
        
        return desc