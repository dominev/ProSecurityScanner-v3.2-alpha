#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
from datetime import datetime
from typing import Optional
from colorama import Fore, Style

def generate_vuln_id(title: str, description: str, timestamp: str) -> str:
    """Генерация уникального ID для уязвимости"""
    data = f"{title}{description}{timestamp}"
    return hashlib.md5(data.encode()).hexdigest()[:8]

def get_timestamp() -> str:
    """Получение текущей временной метки"""
    return datetime.now().isoformat()

def format_duration(start_time: datetime, end_time: Optional[datetime] = None) -> str:
    """Форматирование длительности сканирования"""
    if end_time is None:
        end_time = datetime.now()
    duration = end_time - start_time
    return str(duration)

def get_color_for_level(level: str) -> str:
    """Получение цвета для уровня уязвимости"""
    colors = {
        'CRITICAL': Fore.MAGENTA,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.BLUE,
        'INFO': Fore.CYAN
    }
    return colors.get(level, Fore.WHITE)

def get_icon_for_level(level: str) -> str:
    icons = {
        'CRITICAL': '🔴',
        'HIGH': '❌',
        'MEDIUM': '⚠️',
        'LOW': 'ℹ️',
        'INFO': '📋'
    }
    return icons.get(level, '•')

def sanitize_url(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.replace('.', '_').replace(':', '_')
    return domain

def print_banner():
    """Баннер сканера"""
    banner = f"""
{Fore.MAGENTA}
██████╗  ██████╗ ██╗     ██╗     ██╗███╗   ██╗ ██████╗ 
██╔══██╗██╔═══██╗██║     ██║     ██║████╗  ██║██╔════╝ 
██████╔╝██║   ██║██║     ██║     ██║██╔██╗ ██║██║  ███╗
██╔═══╝ ██║   ██║██║     ██║     ██║██║╚██╗██║██║   ██║
██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
{Fore.YELLOW}Professional Vulnerability Assessment Tool v3.2 - alpha // @dominev
{Fore.RED}⚠️  EDUCATIONAL & ETHICAL USE ONLY{Style.RESET_ALL}
    """
    print(banner)

def print_warning():
    print(f"{Fore.YELLOW}⚠️  WARNING: Use only on systems you own or have permission!{Style.RESET_ALL}\n")