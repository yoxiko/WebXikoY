import sqlite3
import aiohttp
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json

class CVEDatabase:
    def __init__(self, config):
        self.config = config
        self.db_path = "data/cve.db"
        self._init_database()

    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_entries (
                id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT,
                published_date TEXT,
                last_modified TEXT,
                products TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpe_matches (
                cve_id TEXT,
                cpe_string TEXT,
                version_start_including TEXT,
                version_end_excluding TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve_entries (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sync_metadata (
                last_sync TEXT,
                total_records INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()

    async def sync_with_nvd(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        last_sync = cursor.execute("SELECT last_sync FROM sync_metadata").fetchone()
        if last_sync:
            last_sync_date = datetime.fromisoformat(last_sync[0])
            if datetime.now() - last_sync_date < timedelta(hours=24):
                conn.close()
                return
        
        async with aiohttp.ClientSession() as session:
            current_year = datetime.now().year
            for year in range(2002, current_year + 1):
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00.000&pubEndDate={year}-12-31T23:59:59.999"
                
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            await self._process_cve_data(data, cursor)
                except Exception as e:
                    continue
        
        cursor.execute("DELETE FROM sync_metadata")
        cursor.execute("INSERT INTO sync_metadata (last_sync, total_records) VALUES (?, ?)",
                      (datetime.now().isoformat(), cursor.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]))
        
        conn.commit()
        conn.close()

    async def _process_cve_data(self, data: Dict, cursor):
        for vuln in data.get('vulnerabilities', []):
            cve = vuln['cve']
            cve_id = cve['id']
            
            description = cve['descriptions'][0]['value'] if cve['descriptions'] else ''
            
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            cvss_vector = ''
            severity = 'UNKNOWN'
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = 'HIGH' if cvss_score >= 7.0 else 'MEDIUM' if cvss_score >= 4.0 else 'LOW'
            
            products = []
            for config in cve.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        products.append(cpe_match['criteria'])
                        
                        cursor.execute('''
                            INSERT OR REPLACE INTO cpe_matches 
                            (cve_id, cpe_string, version_start_including, version_end_excluding)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            cve_id,
                            cpe_match['criteria'],
                            cpe_match.get('versionStartIncluding'),
                            cpe_match.get('versionEndExcluding')
                        ))
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_entries 
                (id, description, cvss_score, cvss_vector, severity, published_date, last_modified, products)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                description,
                cvss_score,
                cvss_vector,
                severity,
                cve.get('published'),
                cve.get('lastModified'),
                json.dumps(products)
            ))

    def get_cves_for_product(self, product: str, version: str) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ce.* FROM cve_entries ce
            JOIN cpe_matches cm ON ce.id = cm.cve_id
            WHERE cm.cpe_string LIKE ? 
            AND (cm.version_start_including IS NULL OR ? >= cm.version_start_including)
            AND (cm.version_end_excluding IS NULL OR ? < cm.version_end_excluding)
        ''', (f'%{product}%', version, version))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'description': row[1],
                'cvss_score': row[2],
                'cvss_vector': row[3],
                'severity': row[4],
                'published_date': row[5],
                'last_modified': row[6],
                'products': json.loads(row[7]) if row[7] else []
            })
        
        conn.close()
        return results

    def search_cves(self, query: str, severity: str = None) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        sql = "SELECT * FROM cve_entries WHERE description LIKE ?"
        params = [f'%{query}%']
        
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        
        cursor.execute(sql, params)
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'description': row[1],
                'cvss_score': row[2],
                'cvss_vector': row[3],
                'severity': row[4],
                'published_date': row[5],
                'last_modified': row[6],
                'products': json.loads(row[7]) if row[7] else []
            })
        
        conn.close()
        return results