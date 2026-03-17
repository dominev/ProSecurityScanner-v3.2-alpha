#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Конфигурация сканера"""

import yaml
from typing import Optional, Dict, Any
from pathlib import Path


class Config:
    """Глобальная конфигурация сканера"""

    DEFAULT_CONFIG = {
        'scanner': {
            'name': 'ProSecurityScanner',
            'version': '2.0',
            'author': 'Security Team',
            'timeout': 10,
            'max_threads': 10,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProSecurityScanner/2.0'
        },
        'security': {
            'ssl_verify': False,  # Для тестов (в продакшене: True)
            'use_proxy': False,
            'proxies_file': 'proxies.txt',
            'user_agents_file': 'user_agents.txt',
            'min_request_delay': 1.0,
            'max_request_delay': 3.0,
            'max_retries': 3,
            'retry_base_delay': 2.0,
            'randomize_headers': True,
            'debug': False
        },
        'checks': {
            'security_headers': True,
            'ssl_audit': True,
            'info_disclosure': True,
            'sensitive_files': True,
            'entry_points': True,
            'http_methods': True,
            'owasp_top10': True,
            'cms_detection': True
        },
        'sensitive_files': [
            '/.git/config', '/.env', '/backup.zip', '/backup.sql', '/backup.tar.gz',
            '/database.sql', '/dump.sql', '/config.php', '/config.yml', '/config.json',
            '/.htaccess', '/.htpasswd', '/web.config', '/phpinfo.php', '/info.php',
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/pma',
            '/.svn/entries', '/.hg/.hgignore', '/.DS_Store', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/elmah.axd', '/trace.axd', '/server-status', '/server-info',
            '/.bash_history', '/.ssh/authorized_keys', '/id_rsa', '/id_dsa',
            '/wp-config.php', '/configuration.php', '/settings.php',
            '/.aws/credentials', '/.docker/config.json', '/kubeconfig'
        ],
        'risk_levels': {
            'CRITICAL': {'color': '\033[95m', 'weight': 4},
            'HIGH': {'color': '\033[91m', 'weight': 3},
            'MEDIUM': {'color': '\033[93m', 'weight': 2},
            'LOW': {'color': '\033[94m', 'weight': 1},
            'INFO': {'color': '\033[96m', 'weight': 0}
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._deep_copy(self.DEFAULT_CONFIG)
        if config_path:
            self._load_config(config_path)

    def _deep_copy(self, obj: Any) -> Any:
        """Глубокое копирование конфигурации"""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(item) for item in obj]
        return obj

    def _load_config(self, config_path: str):
        """Загрузка конфигурации из YAML файла"""
        try:
            path = Path(config_path)
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    custom_config = yaml.safe_load(f)
                    self._merge_config(custom_config)
            else:
                print(f"⚠️  Конфиг файл не найден: {config_path}")
        except Exception as e:
            print(f"⚠️  Ошибка загрузки конфига: {e}")

    def _merge_config(self, custom: dict):
        """Слияние конфигураций"""
        for key, value in custom.items():
            if key in self.config and isinstance(value, dict) and isinstance(self.config[key], dict):
                self.config[key].update(value)
            else:
                self.config[key] = value

    def get(self, key: str, default=None):
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """Установка значения по ключу"""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def save(self, path: str):
        """Сохранение конфигурации в файл"""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, default_flow_style=False)
        except Exception as e:
            print(f"!!!  Ошибка сохранения конфига: {e}")