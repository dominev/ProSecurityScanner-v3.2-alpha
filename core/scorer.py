#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Система расчета риска уязвимостей (Пофикшено)"""

from typing import Dict, List, Union
from colorama import Fore, Style


class RiskScorer:
    """Калькулятор риска безопасности"""

    # Веса для уровней уязвимостей
    LEVEL_WEIGHTS = {
        'CRITICAL': 25,
        'HIGH': 15,
        'MEDIUM': 5,
        'LOW': 1,
        'INFO': 0
    }

    # Максимальный счет (100)
    MAX_SCORE = 100

    # Пороги для классификации риска
    RISK_THRESHOLDS = {
        'CRITICAL': 75,
        'HIGH': 50,
        'MEDIUM': 25,
        'LOW': 10,
        'MINIMAL': 0
    }

    def __init__(self):
        self.score = 0
        self.risk_level = 'MINIMAL'
        self.details = {}

    def calculate(self, vulnerabilities: List) -> Dict:
        """Расчет общего счета риска"""
        self.score = 0
        self.details = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
        }

        for vuln in vulnerabilities:
            level = vuln.level if hasattr(vuln, 'level') else vuln.get('level', 'INFO')
            self.details[level] = self.details.get(level, 0) + 1
            self.score += self.LEVEL_WEIGHTS.get(level, 0)

        self.score = min(self.score, self.MAX_SCORE)
        self.risk_level = self._get_risk_level(self.score)

        return {
            'score': self.score,
            'risk_level': self.risk_level,
            'details': self.details,
            'verdict': self._get_verdict(),
            'priority': self._get_priority()
        }

    def _get_risk_level(self, score: int) -> str:
        if score >= self.RISK_THRESHOLDS['CRITICAL']:
            return 'CRITICAL'
        elif score >= self.RISK_THRESHOLDS['HIGH']:
            return 'HIGH'
        elif score >= self.RISK_THRESHOLDS['MEDIUM']:
            return 'MEDIUM'
        elif score >= self.RISK_THRESHOLDS['LOW']:
            return 'LOW'
        return 'MINIMAL'

    def _get_verdict(self) -> str:
        verdicts = {
            'CRITICAL': '🔴 НЕМЕДЛЕННОЕ ВМЕШАТЕЛЬСТВО ТРЕБУЕТСЯ',
            'HIGH': '🟠 ТРЕБУЕТСЯ ГЛУБОКИЙ АНАЛИЗ',
            'MEDIUM': '🟡 РЕКОМЕНДУЕТСЯ ПРОВЕРКА',
            'LOW': '🟢 МИНОРНЫЕ ПРОБЛЕМЫ',
            'MINIMAL': '✅ БЕЗОПАСНО (поверхностно)'
        }
        return verdicts.get(self.risk_level, '❓ НЕИЗВЕСТНО')

    def _get_priority(self) -> str:
        priorities = {
            'CRITICAL': 'P0 - Критический приоритет',
            'HIGH': 'P1 - Высокий приоритет',
            'MEDIUM': 'P2 - Средний приоритет',
            'LOW': 'P3 - Низкий приоритет',
            'MINIMAL': 'P4 - Мониторинг'
        }
        return priorities.get(self.risk_level, '❓ Не определен')

    # СТАТИЧЕСКИЕ МЕТОДЫ - не зависят от состояния экземпляра

    @staticmethod
    def get_color(level: str = None, score: int = None) -> str:
        """Получение цвета для уровня риска или счета"""
        if level is None and score is not None:
            level = RiskScorer._get_risk_level_static(score)

        colors = {
            'CRITICAL': Fore.MAGENTA,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'MINIMAL': Fore.GREEN
        }
        return colors.get(level, Fore.WHITE)

    @staticmethod
    def get_bar(score: int, width: int = 20, level: str = None) -> str:

        # Гарантируем, что score - число
        score = int(score) if score else 0
        score = max(0, min(score, RiskScorer.MAX_SCORE))

        # Расчет заполненности
        filled = int((score / RiskScorer.MAX_SCORE) * width)
        filled = max(0, min(filled, width))
        empty = width - filled

        # Цвет по уровню или по счету
        color = RiskScorer.get_color(level, score)
        bar = '█' * filled + '░' * empty

        return f"{color}[{bar}] {score}/{RiskScorer.MAX_SCORE}{Style.RESET_ALL}"

    @staticmethod
    def get_risk_emoji(level: str) -> str:
        """Получение эмодзи для уровня риска"""
        emojis = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '✅'
        }
        return emojis.get(level, '❓')

    @staticmethod
    def _get_risk_level_static(score: int) -> str:
        """Статическая версия определения уровня риска"""
        thresholds = {
            'CRITICAL': 75,
            'HIGH': 50,
            'MEDIUM': 25,
            'LOW': 10,
            'MINIMAL': 0
        }
        if score >= thresholds['CRITICAL']:
            return 'CRITICAL'
        elif score >= thresholds['HIGH']:
            return 'HIGH'
        elif score >= thresholds['MEDIUM']:
            return 'MEDIUM'
        elif score >= thresholds['LOW']:
            return 'LOW'
        return 'MINIMAL'