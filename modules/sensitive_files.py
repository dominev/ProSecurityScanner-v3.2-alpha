#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль поиска чувствительных файлов"""

import queue
import threading
from urllib.parse import urljoin
from typing import List
from core.models import Vulnerability


class SensitiveFilesModule:

    name = "Sensitive Files"
    description = "Check for exposed sensitive files"

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.result = scanner.result

    def check(self) -> List[Vulnerability]:
        vulns = []
        files = self.config.get('sensitive_files', [])

        def check_file(file_path):
            try:
                url = urljoin(self.scanner.target_url, file_path)
                resp = self.scanner.request_handler.get(url, timeout=5, allow_redirects=False)
                self.result.statistics['requests_made'] += 1
                self.result.statistics['files_checked'] += 1

                if resp.status_code == 200 and len(resp.content) > 100:
                    if 'not found' not in resp.text.lower() and '404' not in resp.text.lower():
                        level = 'CRITICAL' if any(
                            x in file_path for x in ['.env', '.git', 'credentials', 'id_rsa', '.aws']) else 'HIGH'
                        return Vulnerability(
                            level=level,
                            category='Sensitive Data Exposure',
                            title=f'Accessible Sensitive File: {file_path}',
                            description=f'Файл доступен публично (Статус: {resp.status_code}, Размер: {len(resp.content)} байт)',
                            recommendation='Удалить файл или ограничить доступ через веб-сервер',
                            evidence=f'URL: {url}',
                            cwe_id='CWE-538',
                            cvss_score=7.5 if level == 'CRITICAL' else 5.3
                        )
            except:
                pass
            return None

        queue_files = queue.Queue()
        for f in files:
            queue_files.put(f)

        def worker():
            while not queue_files.empty():
                file_path = queue_files.get()
                vuln = check_file(file_path)
                if vuln:
                    vulns.append(vuln)
                queue_files.task_done()

        threads = []
        for _ in range(min(self.config.get('scanner.max_threads', 10), len(files))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        queue_files.join()

        return vulns