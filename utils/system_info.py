from __future__ import annotations

import socket
import platform
from dataclasses import dataclass

import psutil


@dataclass
class SystemSnapshot:
    hostname: str
    ip_address: str
    os_name: str
    cpu_percent: float
    memory_percent: float


def get_local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def get_system_snapshot() -> SystemSnapshot:
    return SystemSnapshot(
        hostname=socket.gethostname(),
        ip_address=get_local_ip(),
        os_name=f"{platform.system()} {platform.release()}",
        cpu_percent=psutil.cpu_percent(interval=None),
        memory_percent=psutil.virtual_memory().percent,
    )
