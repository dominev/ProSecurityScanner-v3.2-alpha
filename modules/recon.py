#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль разведки и сбора информации"""

from typing import List
from core.models import Vulnerability

class ReconModule:

    name = "Reconnaissance"
    description = "Information gathering and fingerprinting"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []
        try:
            response = self.scanner.request_handler.get(self.scanner.target_url, timeout=self.config.get('scanner.timeout'))
            self.result.statistics['requests_made'] += 1
            self.result.statistics['pages_scanned'] += 1

            # Сохранение информации
            self.result.info['status_code'] = response.status_code
            self.result.info['server'] = response.headers.get('Server', 'Unknown')
            self.result.info['powered_by'] = response.headers.get('X-Powered-By', 'Unknown')
            self.result.info['content_length'] = len(response.content)
            self.result.info['technologies'] = self._detect_technologies(response)

            # Проверка на редиректы
            if response.history:
                for hist in response.history:
                    if hist.status_code in [301, 302]:
                        vulns.append(Vulnerability(
                            level='INFO',
                            category='Information Disclosure',
                            title='HTTP Redirect Detected',
                            description=f'URL перенаправляет с {hist.url} на {response.url}',
                            recommendation='Убедиться, что редиректы настроены безопасно (HTTPS)',
                            cwe_id='CWE-601'
                        ))

        except Exception as e:
            self.scanner.log(f"Ошибка разведки: {e}", "ERROR")

        return vulns

    def _detect_technologies(self, response) -> List[str]:
        """Определение технологий"""
        techs = []
        content = response.text.lower()
        headers = response.headers

        signatures = {
            'PHP': [headers.get('X-Powered-By', '').lower(), 'php'],
            'ASP.NET': [headers.get('X-Powered-By', '').lower(), 'asp.net'],
            'WordPress': ['wordpress', 'wp-content', 'wp-includes'],
            'Joomla': ['joomla', 'com_content'],
            'Drupal': ['drupal', 'sites/default'],
            'Nginx': [headers.get('Server', '').lower()],
            'Apache': [headers.get('Server', '').lower()],
            'IIS': [headers.get('Server', '').lower()],
            'jQuery': ['jquery'],
            'React': ['react'],
            'Angular': ['angular'],
            'Vue.js': ['vue']
        }

        for tech, patterns in signatures.items():
            if any(pattern in content or pattern in str(headers).lower() for pattern in patterns):
                techs.append(tech)

        return techs