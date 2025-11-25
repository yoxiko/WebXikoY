import asyncio
from scapy.all import sr1, IP, TCP
from typing import List, Dict

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389]

    async def scapy_scan(self, target: str) -> List[int]:
        open_ports = []
        
        for port in self.common_ports:
            if await self._check_port(target, port):
                open_ports.append(port)
        
        return open_ports

    async def _check_port(self, target: str, port: int) -> bool:
        try:
            packet = IP(dst=target)/TCP(dport=port, flags="S")
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: sr1(packet, timeout=self.config.scanner.timeout, verbose=0)
            )
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    rst_pkt = IP(dst=target)/TCP(dport=port, flags="R")
                    await asyncio.get_event_loop().run_in_executor(
                        None, lambda: sr1(rst_pkt, timeout=1, verbose=0)
                    )
                    return True
            return False
        except Exception:
            return False

    async def syn_scan(self, target: str, ports: List[int]) -> List[int]:
        open_ports = []
        semaphore = asyncio.Semaphore(100)
        
        async def scan_port(port):
            async with semaphore:
                if await self._check_port(target, port):
                    open_ports.append(port)
        
        tasks = [scan_port(port) for port in ports]
        await asyncio.gather(*tasks)
        return open_ports