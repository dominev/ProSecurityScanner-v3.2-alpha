#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from datetime import datetime
from typing import Dict, List
from pathlib import Path


class Reporter:
    """Генератор отчетов"""

    def __init__(self, reports_dir: str = 'reports'):
        self.reports_dir = reports_dir
        self._ensure_dir()

    def _ensure_dir(self):
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

    def generate_json_report(self, scan_result: Dict, filename: str) -> str:
        filepath = os.path.join(self.reports_dir, filename)
        try:
            with open(filepath, 'w', encoding='utf-8-sig') as f:  # ✅ UTF-8 с BOM для Windows
                json.dump(scan_result, f, indent=2, ensure_ascii=False)  # ✅ Не экранировать кириллицу
            return filepath
        except Exception as e:
            raise Exception(f"Error saving JSON report: {e}")

    def generate_html_report(self, scan_result: Dict, filename: str) -> str:
        filepath = os.path.join(self.reports_dir, filename)

        html = self._build_html(scan_result)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            return filepath
        except Exception as e:
            raise Exception(f"Error saving HTML report: {e}")

    def _build_html(self, scan_result: Dict) -> str:
        summary = scan_result.get('summary', {})
        vulnerabilities = scan_result.get('vulnerabilities', [])

        html = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_result.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat {{ padding: 15px; border-radius: 5px; text-align: center; color: white; }}
        .critical {{ background: #d63031; }}
        .high {{ background: #e17055; }}
        .medium {{ background: #fdcb6e; color: #333; }}
        .low {{ background: #74b9ff; }}
        .info {{ background: #00cec9; }}
        .vuln {{ border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 5px; border-left: 4px solid #007bff; }}
        .vuln-critical {{ border-left-color: #d63031; }}
        .vuln-high {{ border-left-color: #e17055; }}
        .vuln-medium {{ border-left-color: #fdcb6e; }}
        .vuln-low {{ border-left-color: #74b9ff; }}
        .vuln-info {{ border-left-color: #00cec9; }}
        .label {{ font-weight: bold; color: #555; }}
        .recommendation {{ background: #d4edda; padding: 10px; border-radius: 3px; margin-top: 10px; }}
        .timestamp {{ color: #888; font-size: 0.9em; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; flex: 1; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Scan Report</h1>
        <p class="timestamp">Target: {scan_result.get('target', 'Unknown')} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="stats">
            <div class="stat-box"><strong>Duration:</strong> {scan_result.get('duration', 'N/A')}</div>
            <div class="stat-box"><strong>Requests:</strong> {scan_result.get('statistics', {}).get('requests_made', 0)}</div>
            <div class="stat-box"><strong>Files Checked:</strong> {scan_result.get('statistics', {}).get('files_checked', 0)}</div>
        </div>

        <h2>📊 Summary</h2>
        <div class="summary">
"""

        for level, count in summary.items():
            html += f'<div class="stat {level.lower()}">{level}<br><strong>{count}</strong></div>'

        html += """
        </div>

        <h2>🔍 Vulnerabilities</h2>
"""

        for vuln in vulnerabilities:
            html += f"""
        <div class="vuln vuln-{vuln.get('level', 'info').lower()}">
            <h3>[{vuln.get('level', 'INFO')}] {vuln.get('title', 'Unknown')}</h3>
            <p><span class="label">Category:</span> {vuln.get('category', 'N/A')}</p>
            <p><span class="label">Description:</span> {vuln.get('description', 'N/A')}</p>
            {f'<p><span class="label">Evidence:</span> {vuln.get("evidence", "")}</p>' if vuln.get('evidence') else ''}
            <div class="recommendation">
                <strong>🛡 Recommendation:</strong> {vuln.get('recommendation', 'N/A')}
            </div>
            <p class="timestamp">CWE: {vuln.get('cwe_id', 'N/A')} | CVSS: {vuln.get('cvss_score', 0)} | ID: {vuln.get('id', 'N/A')}</p>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        return html

    def generate_text_report(self, scan_result: Dict, filename: str) -> str:
        """Генерация текстового отчета"""
        filepath = os.path.join(self.reports_dir, filename)

        lines = []
        lines.append("=" * 70)
        lines.append("SECURITY SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {scan_result.get('target', 'Unknown')}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Duration: {scan_result.get('duration', 'N/A')}")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 70)

        summary = scan_result.get('summary', {})
        for level, count in summary.items():
            lines.append(f"{level}: {count}")

        lines.append("")
        lines.append("VULNERABILITIES")
        lines.append("-" * 70)

        for vuln in scan_result.get('vulnerabilities', []):
            lines.append(f"[{vuln.get('level', 'INFO')}] {vuln.get('title', 'Unknown')}")
            lines.append(f"  Category: {vuln.get('category', 'N/A')}")
            lines.append(f"  Description: {vuln.get('description', 'N/A')}")
            lines.append(f"  Recommendation: {vuln.get('recommendation', 'N/A')}")
            lines.append("")

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            return filepath
        except Exception as e:
            raise Exception(f"Error saving text report: {e}")