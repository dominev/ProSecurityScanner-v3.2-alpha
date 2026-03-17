#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProSecurityScanner v3.2 alpha - Professional Vulnerability Assessment Tool
//Reconnaissance/Triage Scanner
"""

import argparse
import sys
import yaml
import json
from core.scanner import ProSecurityScanner
from core.batch_scanner import BatchScanner
from core.utils import print_banner, print_warning
from colorama import Fore, Style


def build_security_config(args) -> dict:
    """Логика конфига безопасности"""
    # Прокси
    proxies_file = 'proxies.txt'
    if args.proxy:
        if args.proxy.startswith(('http://', 'https://', 'socks://', 'socks5://')):
            proxies_file = None
        elif '.' in args.proxy or '/' in args.proxy:
            proxies_file = args.proxy

    # Задержки
    delay_multiplier = 2 if args.stealth else 1

    return {
        'ssl_verify': not args.no_verify,
        'use_proxy': bool(args.proxy),
        'proxy_string': args.proxy if args.proxy and args.proxy.startswith(('http', 'socks')) else None,
        'proxies_file': proxies_file,
        'min_request_delay': args.delay * delay_multiplier,
        'max_request_delay': args.max_delay * delay_multiplier,
        'max_retries': args.retries,
        'retry_base_delay': 2.0,
        'randomize_headers': True,
        'debug': args.debug,
        'stealth_mode': args.stealth
    }


def main():
    parser = argparse.ArgumentParser(
        description='ProSecurityScanner v3.2 alpha - Reconnaissance/Triage Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
  //help

  # Сканирование по одной цели (одиночное)
  python scanner.py https://example.com

  # Fast мод + Stealth
  python scanner.py https://example.com --fast --stealth

  # Прокси + задержка
  python scanner.py https://example.com --proxy "http://user:pass@proxy:8080" --delay 2

  # Массовый скан
  python scanner.py -l targets.txt --min-risk HIGH
        """
    )

    parser.add_argument('target', nargs='?', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-l', '--list', help='File with target URLs (one per line)')
    parser.add_argument('-c', '--config', help='Path to configuration file (YAML)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (only vulnerabilities)')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--version', action='version', version='ProSecurityScanner v3.1')

    # Флаги режимов
    parser.add_argument('--fast', action='store_true', help='Fast mode (skip time-consuming checks)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for batch scan (default: 5)')
    parser.add_argument('--rate-limit', type=float, default=0.5, help='Rate limit between requests (default: 0.5)')
    parser.add_argument('--min-risk', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL'],
                        help='Filter results by minimum risk level')

    # Флаги безопасности/стелс
    parser.add_argument('--proxy', help='Proxy string or path to proxies file')
    parser.add_argument('--delay', type=float, default=1.0, help='Min delay between requests (seconds)')
    parser.add_argument('--max-delay', type=float, default=3.0, help='Max delay between requests (seconds)')
    parser.add_argument('--retries', type=int, default=3, help='Max retry attempts')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification (TESTING ONLY)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode (slower but harder to detect)')

    args = parser.parse_args()

    print_banner()
    print_warning()

    # Конфиг безопасности для всех режимов
    security_config = build_security_config(args)

    # Масс скан
    if args.list:
        config_path = args.config

        if security_config and not config_path:
            pass

        batch_scanner = BatchScanner(
            config_path=config_path,
            max_threads=args.threads,
            rate_limit=args.rate_limit,
            verbose=not args.quiet
        )

        if hasattr(batch_scanner, 'config') and batch_scanner.config:
            batch_scanner.config.config['security'] = {
                **batch_scanner.config.config.get('security', {}),
                **security_config
            }

        try:
            targets = batch_scanner.load_targets(args.list)
            results = batch_scanner.scan_batch(
                targets,
                output_file=args.output or 'batch_scan',
                min_risk=args.min_risk
            )

            if args.output:
                print(f"{Fore.GREEN}Отчет сохранен: {args.output}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}X Ошибка массового сканирования: {e}{Style.RESET_ALL}")
            sys.exit(1)

    # Скан по одиночной цели
    elif args.target:
        scanner = ProSecurityScanner(
            target_url=args.target,
            config_path=args.config,
            verbose=not args.quiet,
            fast_mode=args.fast,
            security_config=security_config
        )

        result = scanner.run()

        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
                print(f"{Fore.GREEN}Отчет сохранен: {args.output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}X Ошибка сохранения отчета: {e}{Style.RESET_ALL}")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()