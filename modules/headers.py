#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль проверки заголовков безопасности"""

from typing import List
from core.models import Vulnerability


class SecurityHeadersModule:

    name = "Security Headers"
    description = "OWASP security headers check"

    HEADERS_CHECKS = {
        'Strict-Transport-Security': {
            'level': 'HIGH',
            'category': 'Security Misconfiguration',
            'title': 'Missing HSTS Header',
            'description': 'HTTP Strict Transport Security не настроен. Возможна атака SSL Stripping.',
            'recommendation': 'Добавить заголовок: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'cwe_id': 'CWE-319',
            'cvss_score': 5.3
        },
        'X-Content-Type-Options': {
            'level': 'MEDIUM',
            'category': 'Security Misconfiguration',
            'title': 'Missing X-Content-Type-Options',
            'description': 'Отсутствует защита от MIME-sniffing.',
            'recommendation': 'Добавить заголовок: X-Content-Type-Options: nosniff',
            'cwe_id': 'CWE-693',
            'cvss_score': 4.3
        },
        'X-Frame-Options': {
            'level': 'MEDIUM',
            'category': 'Clickjacking',
            'title': 'Missing X-Frame-Options',
            'description': 'Сайт может быть встроен в iframe. Риск Clickjacking.',
            'recommendation': 'Добавить заголовок: X-Frame-Options: DENY или SAMEORIGIN',
            'cwe_id': 'CWE-1021',
            'cvss_score': 4.3
        },
        'Content-Security-Policy': {
            'level': 'HIGH',
            'category': 'XSS',
            'title': 'Missing Content Security Policy',
            'description': 'Отсутствует CSP. Высокий риск XSS атак.',
            'recommendation': 'Внедрить строгую Content Security Policy',
            'cwe_id': 'CWE-79',
            'cvss_score': 6.1
        },
        'X-XSS-Protection': {
            'level': 'LOW',
            'category': 'XSS',
            'title': 'Missing X-XSS-Protection',
            'description': 'Устаревший заголовок защиты от XSS.',
            'recommendation': 'Добавить: X-XSS-Protection: 1; mode=block',
            'cwe_id': 'CWE-79',
            'cvss_score': 2.6
        },
        'Referrer-Policy': {
            'level': 'LOW',
            'category': 'Information Disclosure',
            'title': 'Missing Referrer-Policy',
            'description': 'Возможна утечка данных через Referer header.',
            'recommendation': 'Добавить: Referrer-Policy: strict-origin-when-cross-origin',
            'cwe_id': 'CWE-200',
            'cvss_score': 2.6
        },
        'Permissions-Policy': {
            'level': 'LOW',
            'category': 'Security',
            'title': 'Missing Permissions-Policy',
            'description': 'Отсутствует контроль функций браузера.',
            'recommendation': 'Настроить Permissions-Policy для ограничения функций',
            'cwe_id': 'CWE-693',
            'cvss_score': 2.6
        },
        'Cache-Control': {
            'level': 'LOW',
            'category': 'Information Disclosure',
            'title': 'Missing Cache-Control for Sensitive Pages',
            'description': 'Возможное кэширование чувствительных данных.',
            'recommendation': 'Добавить: Cache-Control: no-store, no-cache, must-revalidate',
            'cwe_id': 'CWE-524',
            'cvss_score': 2.6
        }
    }

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []
        try:
            response = self.scanner.request_handler.get(self.scanner.target_url, timeout=self.config.get('scanner.timeout'))
            self.result.statistics['requests_made'] += 1
            headers = response.headers

            for header, check_data in self.HEADERS_CHECKS.items():
                if header not in headers:
                    vulns.append(Vulnerability(
                        level=check_data['level'],
                        category=check_data['category'],
                        title=check_data['title'],
                        description=check_data['description'],
                        recommendation=check_data['recommendation'],
                        cwe_id=check_data['cwe_id'],
                        cvss_score=check_data['cvss_score']
                    ))
        except Exception as e:
            self.scanner.log(f"Ошибка проверки заголовков: {e}", "ERROR")

        return vulns