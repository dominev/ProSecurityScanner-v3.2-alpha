#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль проверок по OWASP (top 10)"""

from urllib.parse import urljoin
from typing import List
from core.models import Vulnerability


class OWASPTop10Module:

    name = "OWASP Top 10"
    description = "Basic checks for OWASP Top 10 vulnerabilities"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []

        try:
            response = self.scanner.request_handler.get(self.scanner.target_url, timeout=self.config.get('scanner.timeout'))
            self.result.statistics['requests_made'] += 1

            # A01:2021 - Broken Access Control
            admin_paths = ['/admin', '/administrator', '/wp-admin', '/manager', '/console']
            for path in admin_paths:
                try:
                    url = urljoin(self.scanner.target_url, path)
                    resp = self.session.get(url, timeout=5, allow_redirects=False)
                    self.result.statistics['requests_made'] += 1
                    if resp.status_code == 200:
                        vulns.append(Vulnerability(
                            level='MEDIUM',
                            category='Broken Access Control',
                            title=f'Admin Panel Accessible: {path}',
                            description='Панель администратора доступна без ограничений',
                            recommendation='Ограничить доступ по IP или добавить аутентификацию',
                            evidence=f'URL: {url}',
                            cwe_id='CWE-284',
                            cvss_score=5.3
                        ))
                        break
                except:
                    pass

            # A05:2021 - Security Misconfiguration
            if 'phpinfo' in response.text.lower():
                vulns.append(Vulnerability(
                    level='HIGH',
                    category='Security Misconfiguration',
                    title='phpinfo() Page Exposed',
                    description='Страница с phpinfo() доступна публично',
                    recommendation='Удалить файл с phpinfo()',
                    evidence='phpinfo pattern detected',
                    cwe_id='CWE-200',
                    cvss_score=5.3
                ))

            # A07:2021 - Identification and Authentication Failures
            if 'login' in response.text.lower() and 'password' in response.text.lower():
                vulns.append(Vulnerability(
                    level='INFO',
                    category='Authentication',
                    title='Login Form Detected',
                    description='Найдена форма входа. Требуется проверка на безопасность.',
                    recommendation='Проверить на brute-force, credential stuffing, MFA',
                    evidence='Login form detected',
                    cwe_id='CWE-287',
                    cvss_score=0.0
                ))

            # A09:2021 - Security Logging and Monitoring Failures
            vulns.append(Vulnerability(
                level='INFO',
                category='Logging & Monitoring',
                title='Logging Configuration Unknown',
                description='Невозможно автоматически проверить настройку логирования',
                recommendation='Убедиться в наличии логирования всех событий безопасности',
                evidence='N/A',
                cwe_id='CWE-778',
                cvss_score=0.0
            ))

        except Exception as e:
            self.scanner.log(f"Ошибка OWASP проверок: {e}", "ERROR")

        return vulns