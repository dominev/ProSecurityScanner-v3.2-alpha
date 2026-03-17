#!/usr/bin/env python3
import json, sys, glob
from datetime import datetime

def parse_latest_report(pattern: str = "reports/scan_*.json"):
    files = sorted(glob.glob(pattern), key=lambda x: x.split('_')[-1].replace('.json', ''))
    if not files:
        print("!!! Отчеты не найдены")
        return

    with open(files[-1], 'r', encoding='utf-8-sig') as f:
        data = json.load(f)

    print(f"\n📊 ОТЧЕТ: {data['target']}")
    print(f"Time/ Длительность: {data['duration']}")
    print(f"Rist/ Счет рисков: {data['risk_assessment']['score']}/100 ({data['risk_assessment']['risk_level']})")
    print(f"Report/ Итог: {data['risk_assessment']['verdict']}\n")

    print("Найденные уязвимости:")
    for v in sorted(data['vulnerabilities'],
                    key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(x['level'], 5)):
        print(f"  [{v['level']}] {v['title']} (CVSS: {v['cvss_score']})")

    return data


if __name__ == '__main__':
    parse_latest_report(sys.argv[1] if len(sys.argv) > 1 else "reports/scan_*.json")