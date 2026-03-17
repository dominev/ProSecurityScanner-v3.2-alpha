#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль проверки HTTP методов"""

from typing import List
from core.models import Vulnerability


class HTTPMethodsModule:

    name = "HTTP Methods"
    description = "Check allowed HTTP methods"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []

        try:
            resp = self.session.options(self.scanner.target_url, timeout=10)
            self.result.statistics['requests_made'] += 1
            allowed = resp.headers.get('Allow', '')
            public_methods = resp.headers.get('Public', '')

            all_methods = ', '.join(filter(None, [allowed, public_methods])).upper()

            dangerous_methods = ['TRACE', 'TRACK', 'DEBUG', 'CONNECT']
            risky_methods = ['PUT', 'DELETE', 'PATCH']

            for method in dangerous_methods:
                if method in all_methods:
                    vulns.append(Vulnerability(
                        level='MEDIUM',
                        category='HTTP Methods',
                        title=f'Dangerous HTTP Method Enabled: {method}',
                        description=f'Метод {method} может быть использован для атак',
                        recommendation=f'Отключить метод {method} в конфигурации сервера',
                        evidence=f'Allowed methods: {all_methods}',
                        cwe_id='CWE-693',
                        cvss_score=4.3
                    ))

            for method in risky_methods:
                if method in all_methods:
                    vulns.append(Vulnerability(
                        level='LOW',
                        category='HTTP Methods',
                        title=f'HTTP Method {method} Enabled',
                        description=f'Метод {method} разрешен. Убедиться в необходимости.',
                        recommendation='Ограничить методы только необходимыми (GET, POST)',
                        evidence=f'Allowed methods: {all_methods}',
                        cwe_id='CWE-693',
                        cvss_score=2.6
                    ))

        except Exception as e:
            self.scanner.log(f"Ошибка проверки методов: {e}", "ERROR")

        return vulns