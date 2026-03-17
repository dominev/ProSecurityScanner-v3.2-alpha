#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль проверки на утечку инфы"""

import re
from typing import List
from core.models import Vulnerability


class InfoDisclosureModule:

    name = "Information Disclosure"
    description = "Check for information leakage"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []
        try:
            response = self.scanner.request_handler.get(self.scanner.target_url, timeout=self.config.get('scanner.timeout'))
            self.result.statistics['requests_made'] += 1

            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')

            if server and server != 'Unknown':
                vulns.append(Vulnerability(
                    level='LOW',
                    category='Information Disclosure',
                    title='Server Version Disclosure',
                    description=f'Сервер выдает информацию о себе: {server}',
                    recommendation='Скрыть версию сервера в конфигурации',
                    evidence=server,
                    cwe_id='CWE-200',
                    cvss_score=2.6
                ))

            if powered_by and powered_by != 'Unknown':
                vulns.append(Vulnerability(
                    level='LOW',
                    category='Information Disclosure',
                    title='Technology Disclosure',
                    description=f'Раскрыта технология: {powered_by}',
                    recommendation='Отключить заголовок X-Powered-By',
                    evidence=powered_by,
                    cwe_id='CWE-200',
                    cvss_score=2.6
                ))

            error_patterns = [
                (r'sql\s*(syntax|error|exception)', 'SQL Error Detected'),
                (r'mysql_fetch\w*', 'MySQL Function Exposed'),
                (r'warning\s*:', 'PHP Warning Detected'),
                (r'fatal\s*error', 'Fatal Error Detected'),
                (r'stack\s*trace', 'Stack Trace Exposed'),
                (r'exception\s+in', 'Exception Details Exposed'),
                (r'debug\s*mode', 'Debug Mode Enabled'),
                (r'access\s*denied.*admin', 'Admin Path Disclosure')
            ]

            for pattern, title in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        level='MEDIUM',
                        category='Information Disclosure',
                        title=title,
                        description='Найдены сообщения об ошибках или отладочная информация',
                        recommendation='Отключить подробные ошибки в продакшене',
                        evidence='Pattern matched in response',
                        cwe_id='CWE-209',
                        cvss_score=4.3
                    ))
                    break

        except Exception as e:
            self.scanner.log(f"Ошибка проверки утечек: {e}", "ERROR")

        return vulns