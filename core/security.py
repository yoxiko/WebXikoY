import hashlib
import hmac
import asyncio
from typing import Optional
from contextlib import asynccontextmanager
import os

class SecurityManager:
    def __init__(self, config):
        self.config = config
        self.rate_limits = {}
    
    def generate_scope_token(self, target: str) -> str:
        secret = os.urandom(32)
        return hmac.new(secret, target.encode(), hashlib.sha256).hexdigest()
    
    def verify_scope(self, target: str, token: str) -> bool:
        if not self.config.security.scope_verification:
            return True
        expected = self.generate_scope_token(target)
        return hmac.compare_digest(expected, token)
    
    async def rate_limit_check(self, identifier: str) -> bool:
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []
        
        now = asyncio.get_event_loop().time()
        window = [t for t in self.rate_limits[identifier] if now - t < 60]
        
        if len(window) >= self.config.scanner.rate_limit:
            return False
        
        window.append(now)
        self.rate_limits[identifier] = window
        return True
    
    @asynccontextmanager
    async def isolated_execution(self):
        if self.config.security.process_isolation:
            import multiprocessing
            ctx = multiprocessing.get_context('spawn')
            queue = ctx.Queue()
            
            def worker(q):
                result = yield
                q.put(result)
            
            process = ctx.Process(target=worker, args=(queue,))
            process.start()
            try:
                yield
            finally:
                process.terminate()
                process.join()
        else:
            yield
    
    def encrypt_data(self, data: str) -> bytes:
        if not self.config.security.data_encryption:
            return data.encode()
        
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        if not self.config.security.data_encryption:
            return encrypted_data.decode()
        
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()