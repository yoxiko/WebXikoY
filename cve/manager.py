import asyncio
import json
from typing import List, Dict, Any
from .database import CVEDatabase

class CVEManager:
    def __init__(self, config):
        self.config = config
        self.db = CVEDatabase(config)

    async def initialize(self):
        await self.db.sync_with_nvd()

    async def get_cves_for_service(self, service_name: str, version: str) -> List[Dict[str, Any]]:
        product_mapping = {
            'apache': 'apache:http_server',
            'nginx': 'nginx:nginx',
            'openssh': 'openssh:openssh',
            'mysql': 'mysql:mysql',
            'postgresql': 'postgresql:postgresql',
            'microsoft-iis': 'microsoft:iis',
            'tomcat': 'apache:tomcat'
        }
        
        normalized_name = service_name.lower()
        cpe_product = product_mapping.get(normalized_name, normalized_name)
        
        return self.db.get_cves_for_product(cpe_product, version)

    async def analyze_vulnerabilities(self, services: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total': 0
        }
        
        for service in services:
            service_name = service.get('name', '')
            version = service.get('version', 'unknown')
            
            if service_name and version != 'unknown':
                cves = await self.get_cves_for_service(service_name, version)
                
                for cve in cves:
                    severity = cve.get('severity', 'LOW').lower()
                    if severity in results:
                        cve_info = {
                            'id': cve['id'],
                            'service': service_name,
                            'version': version,
                            'port': service.get('port'),
                            'cvss_score': cve['cvss_score'],
                            'description': cve['description']
                        }
                        results[severity].append(cve_info)
                        results['total'] += 1
        
        return results

    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        conn = self.db._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cve_entries WHERE id = ?', (cve_id,))
        row = cursor.fetchone()
        
        if row:
            return {
                'id': row[0],
                'description': row[1],
                'cvss_score': row[2],
                'cvss_vector': row[3],
                'severity': row[4],
                'published_date': row[5],
                'last_modified': row[6],
                'products': json.loads(row[7]) if row[7] else []
            }
        
        conn.close()
        return {}

    async def get_statistics(self) -> Dict[str, Any]:
        conn = self.db._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity')
        severity_stats = dict(cursor.fetchall())
        
        cursor.execute('SELECT COUNT(*) FROM cve_entries')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT AVG(cvss_score) FROM cve_entries')
        avg_cvss = cursor.fetchone()[0] or 0.0
        
        conn.close()
        
        return {
            'total_cves': total,
            'severity_distribution': severity_stats,
            'average_cvss': round(avg_cvss, 2),
            'last_sync': self._get_last_sync_date()
        }

    def _get_last_sync_date(self):
        conn = self.db._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT last_sync FROM sync_metadata')
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None