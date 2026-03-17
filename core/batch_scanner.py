#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модуль масс скана"""

import threading
import queue
import time
import json
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
from colorama import Fore, Style
from tqdm import tqdm

from .scanner import ProSecurityScanner, ScanResult
from .scorer import RiskScorer
from .reporter import Reporter
from .utils import sanitize_url


class BatchScanner:

    def __init__(self, config_path: Optional[str] = None,
                 max_threads: int = 5,
                 rate_limit: float = 0.5,
                 verbose: bool = True,
                 security_config: Optional[Dict] = None):
        self.config_path = config_path
        self.max_threads = max_threads
        self.rate_limit = rate_limit  # Задержка между запросами (сек)
        self.verbose = verbose
        self.results: List[Dict] = []
        self.reporter = Reporter()
        self.lock = threading.Lock()

    def load_targets(self, file_path: str) -> List[str]:
        """Load из файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return targets
        except Exception as e:
            raise Exception(f"Ошибка загрузки файла целей: {e}")

    def scan_target(self, target: str, progress_bar: tqdm = None) -> Dict:
        """Сканирование одной цели"""
        try:
            scanner = ProSecurityScanner(
                target_url=target,
                config_path=self.config_path,
                verbose=False,
                security_config=self.security_config # Тихий режим для батча
            )
            result = scanner.run()

            # Расчет риска
            scorer = RiskScorer()
            risk_data = scorer.calculate(result.vulnerabilities)

            scan_data = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'duration': result.get_duration(),
                'risk_score': risk_data['score'],
                'risk_level': risk_data['risk_level'],
                'verdict': risk_data['verdict'],
                'priority': risk_data['priority'],
                'vulnerabilities_count': len(result.vulnerabilities),
                'vulnerabilities_summary': risk_data['details'],
                'vulnerabilities': [v.to_dict() for v in result.vulnerabilities]
            }

            with self.lock:
                self.results.append(scan_data)

            if progress_bar:
                progress_bar.set_postfix({
                    'Risk': f"{risk_data['score']}",
                    'Level': risk_data['risk_level']
                })

            # Rate limiting
            time.sleep(self.rate_limit)

            return scan_data

        except Exception as e:
            error_data = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'risk_score': 0,
                'risk_level': 'ERROR'
            }
            with self.lock:
                self.results.append(error_data)
            return error_data

    def scan_batch(self, targets: List[str], output_file: Optional[str] = None,
                   min_risk: str = None) -> List[Dict]:
        """Масс скан списка целей"""
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}!!! ЗАПУСК ПАКЕТНОГО СКАНИРОВАНИЯ{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"Целей: {len(targets)}")
        print(f"Потоков: {self.max_threads}")
        print(f"Rate Limit: {self.rate_limit}s между запросами")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")

        # Очередь целей
        target_queue = queue.Queue()
        for target in targets:
            target_queue.put(target)

        # Прогресс бар
        pbar = tqdm(total=len(targets), desc="Сканирование",
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')

        def worker():
            while True:
                try:
                    target = target_queue.get(timeout=1)
                    self.scan_target(target, pbar)
                    target_queue.task_done()
                except queue.Empty:
                    break
                except Exception:
                    break

        # Запуск потоков
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Ожидание завершения
        target_queue.join()
        pbar.close()

        for t in threads:
            t.join()

        # Фильтрация по риску
        if min_risk:
            risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']
            min_index = risk_order.index(min_risk) if min_risk in risk_order else 0
            self.results = [r for r in self.results
                            if risk_order.index(r.get('risk_level', 'MINIMAL')) <= min_index]

        # Сохранение отчета
        if output_file:
            self._save_batch_report(output_file)

        # Итоговая статистика
        self._print_batch_summary()

        return self.results

    def _save_batch_report(self, output_file: str):
        """Сохранение отчета о масс скане"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # JSON отчет
        json_file = f"{output_file}_{timestamp}.json"
        report_data = {
            'scan_type': 'batch',
            'timestamp': datetime.now().isoformat(),
            'total_targets': len(self.results),
            'results': self.results,
            'summary': self._get_batch_summary()
        }

        try:
            Path('reports').mkdir(parents=True, exist_ok=True)
            with open(f'reports/{json_file}', 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"{Fore.RED}Ошибка сохранения отчета: {e}{Style.RESET_ALL}")

    def _get_batch_summary(self) -> Dict:
        """Сводка"""
        summary = {
            'total': len(self.results),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'minimal': 0,
            'errors': 0,
            'average_score': 0
        }

        total_score = 0
        for result in self.results:
            level = result.get('risk_level', 'MINIMAL').lower()
            if level in summary:
                summary[level] += 1
            elif level == 'error':
                summary['errors'] += 1

            total_score += result.get('risk_score', 0)

        if self.results:
            summary['average_score'] = round(total_score / len(self.results), 2)

        return summary

    def _print_batch_summary(self):
        summary = self._get_batch_summary()

        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}📊 ИТОГИ ПАКЕТНОГО СКАНИРОВАНИЯ{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.WHITE}Всего целей: {summary['total']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Средний риск: {summary['average_score']}/100{Style.RESET_ALL}\n")

        # Таблица рисков
        print(f"{'Уровень':<15} {'Количество':<15} {'Визуализация'}")
        print(f"{'-' * 50}")

        risk_colors = {
            'critical': Fore.MAGENTA,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.BLUE,
            'minimal': Fore.GREEN,
            'errors': Fore.WHITE
        }

        for level in ['critical', 'high', 'medium', 'low', 'minimal', 'errors']:
            count = summary.get(level, 0)
            color = risk_colors.get(level, Fore.WHITE)
            bar = '█' * count if count > 0 else '░'
            emoji = RiskScorer.get_risk_emoji(level.upper())
            print(f"{color}{emoji} {level.upper():<13} {count:<15} {bar}{Style.RESET_ALL}")

        # Итог топа риск целей
        print(f"\n{Fore.YELLOW}🔥 ТОП-5 НАИБОЛЕЕ РИСКОВАННЫХ ЦЕЛЕЙ:{Style.RESET_ALL}")
        sorted_results = sorted(self.results, key=lambda x: x.get('risk_score', 0), reverse=True)[:5]

        for i, result in enumerate(sorted_results, 1):
            score = result.get('risk_score', 0)
            level = result.get('risk_level', 'N/A')
            target = result.get('target', 'Unknown')
            color = RiskScorer().get_color() if score > 50 else Fore.GREEN
            print(f"  {i}. {color}{target:<40} Score: {score}/100 ({level}){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")