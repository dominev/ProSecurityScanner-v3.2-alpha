#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from typing import List
from .utils import generate_vuln_id, get_timestamp


class Vulnerability:
    """Модель уязвимости"""

    def __init__(self, level: str, category: str, title: str,
                 description: str, recommendation: str,
                 evidence: str = '', cwe_id: str = '', cvss_score: float = 0.0):
        self.level = level
        self.category = category
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.evidence = evidence
        self.cwe_id = cwe_id
        self.cvss_score = cvss_score
        self.timestamp = get_timestamp()
        self.id = generate_vuln_id(title, description, self.timestamp)

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'level': self.level,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp
        }


class ScanResult:
    """Результаты сканирования"""

    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()
        self.end_time = None
        self.vulnerabilities: List[Vulnerability] = []
        self.info = {}
        self.statistics = {
            'requests_made': 0,
            'pages_scanned': 0,
            'files_checked': 0
        }
        self.risk_score = None

    def add_vuln(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)

    def finish(self):
        """Завершение сканирования и расчет риска"""
        self.end_time = datetime.now()
        # Импортируем локально внутри метода, чтобы избежать циклического импорта
        from .scorer import RiskScorer
        scorer = RiskScorer()
        self.risk_score = scorer.calculate(self.vulnerabilities)

    def get_duration(self) -> str:
        if self.end_time:
            duration = self.end_time - self.start_time
            return str(duration)
        return 'N/A'

    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'scan_start': self.start_time.isoformat(),
            'scan_end': self.end_time.isoformat() if self.end_time else None,
            'duration': self.get_duration(),
            'statistics': self.statistics,
            'info': self.info,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'summary': self.get_summary(),
            'risk_assessment': self.risk_score
        }

    def get_summary(self) -> dict:
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in self.vulnerabilities:
            summary[vuln.level] = summary.get(vuln.level, 0) + 1
        return summary