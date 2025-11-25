import logging
import ipaddress
from urllib.parse import urlparse
import socket

def setup_logging(level=logging.INFO, log_file=None):
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        try:
            urlparse(target)
            return True
        except:
            return False

def is_port_open(target, port, timeout=5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0
    except:
        return False

def format_cvss_score(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"