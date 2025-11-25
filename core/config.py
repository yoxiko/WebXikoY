import os
import yaml
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class ScannerConfig:
    max_hosts: int = 1000
    timeout: int = 10
    max_retries: int = 3
    rate_limit: int = 50

@dataclass
class SecurityConfig:
    process_isolation: bool = True
    data_encryption: bool = True
    scope_verification: bool = True

class ConfigManager:
    def __init__(self):
        self.scanner = ScannerConfig()
        self.security = SecurityConfig()
        self._load_config()
    
    def _load_config(self):
        config_paths = [
            '/etc/webxikoy/config.yaml',
            './config/webxikoy.yaml',
            os.path.expanduser('~/.webxikoy/config.yaml')
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    config_data = yaml.safe_load(f)
                    self._update_from_dict(config_data)
                break
    
    def _update_from_dict(self, config_dict: Dict[str, Any]):
        if not config_dict:
            return
            
        scanner_config = config_dict.get('scanner', {})
        security_config = config_dict.get('security', {})
        
        for key, value in scanner_config.items():
            if hasattr(self.scanner, key):
                setattr(self.scanner, key, value)
        
        for key, value in security_config.items():
            if hasattr(self.security, key):
                setattr(self.security, key, value)