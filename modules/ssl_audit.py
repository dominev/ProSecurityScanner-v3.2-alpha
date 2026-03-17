#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль аудит SSL/TLS"""

import ssl
import socket
from urllib.parse import urlparse
from typing import List
from core.models import Vulnerability


class SSLAuditModule:

    name = "SSL/TLS Audit"
    description = "Check SSL/TLS security configuration"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []

        if not self.scanner.target_url.startswith('https'):
            vulns.append(Vulnerability(
                level='HIGH',
                category='Transport Security',
                title='No HTTPS Enabled',
                description='Сайт работает без шифрования HTTPS',
                recommendation='Установить SSL сертификат и настроить редирект на HTTPS',
                cwe_id='CWE-319',
                cvss_score=5.3
            ))
            return vulns

        try:
            hostname = urlparse(self.scanner.target_url).netloc.split(':')[0]

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

                    self.result.info['ssl_version'] = version
                    self.result.info['ssl_cipher'] = cipher[0] if cipher else 'Unknown'

                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulns.append(Vulnerability(
                            level='CRITICAL',
                            category='Weak Encryption',
                            title=f'Outdated TLS Version: {version}',
                            description=f'Используется устаревший и небезопасный протокол',
                            recommendation='Включить TLS 1.2 или TLS 1.3',
                            evidence=f'Current version: {version}',
                            cwe_id='CWE-326',
                            cvss_score=7.5
                        ))

                    if cipher and 'RC4' in cipher[0]:
                        vulns.append(Vulnerability(
                            level='HIGH',
                            category='Weak Encryption',
                            title='Weak Cipher Suite Detected',
                            description=f'Используется слабый шифр: {cipher[0]}',
                            recommendation='Отключить слабые шифры в конфигурации сервера',
                            evidence=f'Cipher: {cipher[0]}',
                            cwe_id='CWE-326',
                            cvss_score=5.3
                        ))

        except ssl.SSLError as e:
            vulns.append(Vulnerability(
                level='HIGH',
                category='Transport Security',
                title='SSL Certificate Error',
                description=f'Ошибка SSL сертификата: {str(e)}',
                recommendation='Проверить и обновить SSL сертификат',
                evidence=str(e),
                cwe_id='CWE-295',
                cvss_score=5.3
            ))
        except Exception as e:
            self.scanner.log(f"Ошибка SSL аудита: {e}", "ERROR")

        return vulns