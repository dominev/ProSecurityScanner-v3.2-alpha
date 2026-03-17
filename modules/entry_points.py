#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль поиска точек ввода данных"""

import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import List
from core.models import Vulnerability


class EntryPointsModule:

    name = "Entry Points"
    description = "Discover input vectors for attacks"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []

        try:
            response = self.scanner.request_handler.get(self.scanner.target_url, timeout=self.config.get('scanner.timeout'))
            self.result.statistics['requests_made'] += 1
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            if forms:
                form_actions = [f.get('action', 'N/A') for f in forms]
                vulns.append(Vulnerability(
                    level='INFO',
                    category='Entry Points',
                    title='Forms Detected',
                    description=f'Найдено форм для ввода: {len(forms)}',
                    recommendation='Проверить все формы на валидацию, санитизацию и CSRF защиту',
                    evidence=f'Forms: {form_actions[:5]}',
                    cwe_id='CWE-20',
                    cvss_score=0.0
                ))

            inputs = soup.find_all('input')
            input_types = {}
            for inp in inputs:
                inp_type = inp.get('type', 'text')
                input_types[inp_type] = input_types.get(inp_type, 0) + 1

            if input_types:
                self.result.info['input_fields'] = input_types

            parsed = urlparse(self.scanner.target_url)
            if parsed.query:
                params = parsed.query.split('&')
                vulns.append(Vulnerability(
                    level='INFO',
                    category='Entry Points',
                    title='URL Parameters Detected',
                    description=f'Найдены параметры в URL: {len(params)}',
                    recommendation='Проверить параметры на Injection уязвимости',
                    evidence=f'Parameters: {parsed.query}',
                    cwe_id='CWE-20',
                    cvss_score=0.0
                ))

            reflective_patterns = [
                r'<input[^>]*value\s*=\s*["\'][^"\']*["\']',
                r'<div[^>]*>[^<]*\{[^}]*\}[^<]*</div>',
                r'document\.write\s*\(',
                r'innerHTML\s*='
            ]

            for pattern in reflective_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        level='INFO',
                        category='XSS Potential',
                        title='Reflective Context Detected',
                        description='Найдены места потенциального отражения данных',
                        recommendation='Проверить экранирование вывода в этих местах',
                        evidence='Pattern matched in HTML',
                        cwe_id='CWE-79',
                        cvss_score=0.0
                    ))
                    break

        except Exception as e:
            self.scanner.log(f"Ошибка поиска точек входа: {e}", "ERROR")

        return vulns