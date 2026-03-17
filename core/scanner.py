#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Основной класс сканера (Ядро системы)"""

import requests
from typing import Optional, List, Dict
from datetime import datetime
from colorama import Fore, Style

from .models import Vulnerability, ScanResult
from .config import Config
from .reporter import Reporter
from .scorer import RiskScorer
from .utils import get_color_for_level, get_icon_for_level, sanitize_url
from .request_handler import RequestHandler

from modules.recon import ReconModule
from modules.headers import SecurityHeadersModule
from modules.ssl_audit import SSLAuditModule
from modules.disclosure import InfoDisclosureModule
from modules.sensitive_files import SensitiveFilesModule
from modules.entry_points import EntryPointsModule
from modules.http_methods import HTTPMethodsModule
from modules.owasp_checks import OWASPTop10Module


class ProSecurityScanner:
    """Основной класс сканера"""

    # Модуль Fast мод
    FAST_MODE_MODULES = [
        'Reconnaissance',
        'Security Headers',
        'Information Disclosure'
    ]

    def __init__(self, target_url: str, config_path: Optional[str] = None,
                 verbose: bool = True, fast_mode: bool = False,
                 security_config: Optional[Dict] = None):
        # Очистка и нормализация URL
        self.target_url = target_url.strip() if target_url else ''
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = f'https://{self.target_url}'

        # Загрузка конфигурации
        self.config = Config(config_path)

        if security_config:
            existing = self.config.config.get('security', {})
            self.config.config['security'] = {**existing, **security_config}

        self.verbose = verbose
        self.fast_mode = fast_mode

        self.request_handler = RequestHandler(self.config.get('security', {}))

        self.result = ScanResult(self.target_url)
        self.reporter = Reporter()
        self.modules = []
        self._init_modules()

    def _init_modules(self):
        """Инициализация модулей проверок"""
        all_modules = [
            ReconModule(self),
            SecurityHeadersModule(self),
            InfoDisclosureModule(self),
            SensitiveFilesModule(self),
            SSLAuditModule(self),
            EntryPointsModule(self),
            HTTPMethodsModule(self),
            OWASPTop10Module(self)
        ]

        if self.fast_mode:
            # Только быстрые модули
            self.modules = [m for m in all_modules if m.name in self.FAST_MODE_MODULES]
        else:
            self.modules = all_modules

    def log(self, message: str, level: str = "INFO"):
        """Вывод логов"""
        if not self.verbose and level == "DEBUG":
            return

        icon = get_icon_for_level(level)
        color = get_color_for_level(level)

        print(f"{color}[{icon} {level}] {message}{Style.RESET_ALL}")

    def run(self) -> ScanResult:
        """Запуск сканирования"""
        mode_text = "⚡ БЫСТРЫЙ РЕЖИМ" if self.fast_mode else "🔍 ПОЛНЫЙ РЕЖИМ"
        stealth_text = " 🥷 STEALTH" if self.config.get('security.stealth_mode') else ""

        self.log(f"🎯 Цель: {self.target_url} [{mode_text}{stealth_text}]", "INFO")
        self.log(f"📦 Модулей загружено: {len(self.modules)}", "INFO")

        # Инфо о настройках безопасности в отладочном режиме
        if self.config.get('security.debug'):
            sec = self.config.get('security', {})
            self.log(f"🔐 SSL Verify: {sec.get('ssl_verify')}", "DEBUG")
            self.log(f"🔐 Proxy: {sec.get('use_proxy')}", "DEBUG")
            self.log(f"⏱️  Delay: {sec.get('min_request_delay')}-{sec.get('max_request_delay')}s", "DEBUG")

        print(f"{Fore.MAGENTA}{'=' * 70}{Style.RESET_ALL}")

        for module in self.modules:
            module_name = module.name.lower().replace(' ', '_')
            if self.config.get(f'checks.{module_name}'):
                self.log(f"🔍 Запуск модуля: {module.name}", "INFO")

                try:
                    vulns = module.check()
                    for vuln in vulns:
                        self.result.add_vuln(vuln)
                        self._print_vuln(vuln)
                except Exception as e:
                    self.log(f"Ошибка модуля {module.name}: {e}", "ERROR")

        self.result.finish()
        self._print_summary()
        self._save_report()

        return self.result

    def _print_vuln(self, vuln: Vulnerability):
        """Вывод информации об уязвимости"""
        color = get_color_for_level(vuln.level)

        print(f"\n{color}[{vuln.level}] {vuln.category}: {vuln.title}{Style.RESET_ALL}")
        print(f"    {vuln.description}")
        if vuln.evidence:
            print(f"    {Fore.WHITE}Evidence: {vuln.evidence}{Style.RESET_ALL}")
        print(f"    {Fore.GREEN}🛡 Fix: {vuln.recommendation}{Style.RESET_ALL}")
        if vuln.cwe_id:
            print(f"    {Fore.YELLOW}CWE: {vuln.cwe_id}{Style.RESET_ALL}")
        if vuln.cvss_score > 0:
            print(f"    {Fore.RED}CVSS: {vuln.cvss_score}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'-'*70}{Style.RESET_ALL}")

    def _print_summary(self):
        """Вывод итоговой сводки с Risk Score"""
        print(f"\n{Fore.MAGENTA}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}📊 ИТОГОВЫЙ ОТЧЕТ{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'=' * 70}{Style.RESET_ALL}")

        summary = self.result.get_summary()
        total = sum(summary.values())

        print(f"\n{Fore.WHITE}Время сканирования: {self.result.get_duration()}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Запросов сделано: {self.result.statistics['requests_made']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Файлов проверено: {self.result.statistics['files_checked']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Всего найдено: {total}{Style.RESET_ALL}\n")

        # Таблица уязвимостей
        for level, count in summary.items():
            color = get_color_for_level(level)
            bar = '█' * count if count > 0 else '░'
            emoji = RiskScorer.get_risk_emoji(level)
            print(f"{color}{emoji} {level:10}: {count:3} {bar}{Style.RESET_ALL}")

        # Risk Score
        if self.result.risk_score:
            print(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")

            score = self.result.risk_score.get('score', 0)
            level = self.result.risk_score.get('risk_level', 'MINIMAL')

            print(f"{Fore.WHITE}🎯 RISK SCORE:{Style.RESET_ALL} {RiskScorer.get_bar(score, level=level)}")
            print(
                f"{Fore.WHITE}📈 Уровень риска:{Style.RESET_ALL} {RiskScorer.get_color(level)}{level}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}⚡ Вердикт:{Style.RESET_ALL} {self.result.risk_score['verdict']}")
            print(f"{Fore.WHITE}📋 Приоритет:{Style.RESET_ALL} {self.result.risk_score['priority']}")

        print(f"\n{Fore.MAGENTA}{'=' * 70}{Style.RESET_ALL}")

    def _save_report(self):
        """Сохранение отчетов"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = sanitize_url(self.target_url)
        mode = '_fast' if self.fast_mode else ''
        stealth = '_stealth' if self.config.get('security.stealth_mode') else ''

        try:
            # JSON отчет
            json_file = f'scan_{domain}{mode}{stealth}_{timestamp}.json'
            json_path = self.reporter.generate_json_report(self.result.to_dict(), json_file)
            self.log(f"💾 JSON отчет: {json_path}", "SUCCESS")

            # HTML отчет
            html_file = f'scan_{domain}{mode}{stealth}_{timestamp}.html'
            html_path = self.reporter.generate_html_report(self.result.to_dict(), html_file)
            self.log(f"💾 HTML отчет: {html_path}", "SUCCESS")

        except Exception as e:
            self.log(f"Ошибка сохранения отчетов: {e}", "ERROR")