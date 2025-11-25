import ssl
import socket
from typing import Dict, Any
from datetime import datetime

class TLSAnalyzer:
    def __init__(self, config):
        self.config = config

    async def analyze_tls(self, target: str, port: int) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=self.config.scanner.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'tls_version': ssock.version(),
                        'cipher_suite': cipher[0] if cipher else 'unknown',
                        'certificate': self._parse_certificate(cert),
                        'supported_protocols': await self._check_protocols(target, port)
                    }
        except Exception:
            return {}

    def _parse_certificate(self, cert: Dict) -> Dict[str, Any]:
        if not cert:
            return {}
        
        return {
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'not_before': self._parse_date(cert['notBefore']),
            'not_after': self._parse_date(cert['notAfter']),
            'san': cert.get('subjectAltName', [])
        }

    def _parse_date(self, date_str: str) -> str:
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').isoformat()

    async def _check_protocols(self, target: str, port: int) -> Dict[str, bool]:
        protocols = {
            'SSLv2': False,
            'SSLv3': False, 
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        for protocol_name, context in self._get_protocol_contexts().items():
            try:
                with socket.create_connection((target, port), timeout=self.config.scanner.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        protocols[protocol_name] = True
            except Exception:
                continue
                
        return protocols

    def _get_protocol_contexts(self):
        return {
            'TLSv1.3': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            'TLSv1.2': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            'TLSv1.1': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            'TLSv1.0': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        }