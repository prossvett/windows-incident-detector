# reporter.py
# Модуль формирования отчётов HTML и CSV

import csv
import os
from datetime import datetime
from config import REPORTS_DIR


class Reporter:
    def __init__(self, db):
        self.db = db
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def _severity_class(self, severity):
        return severity if severity in ('critical', 'high', 'medium', 'low') else 'low'

    def generate_html(self, incidents, filename=None):
        if not filename:
            filename = os.path.join(
                REPORTS_DIR,
                f"report_{datetime.now():%Y%m%d_%H%M%S}.html")

        html = ['<html><head><meta charset="utf-8">',
                '<title>Отчёт о инцидентах безопасности</title>',
                '<style>',
                'body { font-family: Arial, sans-serif; margin: 20px; }',
                'table { border-collapse: collapse; width: 100%; }',
                'th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }',
                'th { background: #f0f0f0; }',
                '.critical { background: #ffcccc; }',
                '.high { background: #ffe0b3; }',
                '.medium { background: #ffffcc; }',
                '.low { background: #e6ffe6; }',
                '</style></head><body>',
                '<h1>Отчёт о выявленных инцидентах</h1>',
                f'<p>Дата формирования: {datetime.now():%Y-%m-%d %H:%M:%S}</p>',
                '<table>',
                '<tr><th>ID</th><th>Время</th><th>Event ID</th>'
                '<th>Правило</th><th>Критичность</th><th>Описание</th>'
                '<th>Источник</th><th>Статус</th></tr>']

        for inc in incidents:
            cls = self._severity_class(inc[4])
            html.append(
                f'<tr class="{cls}">'
                f'<td>{inc[0]}</td><td>{inc[1]}</td><td>{inc[2]}</td>'
                f'<td>{inc[3]}</td><td>{inc[4]}</td><td>{inc[5]}</td>'
                f'<td>{inc[6]}</td><td>{inc[8]}</td></tr>')

        html.append('</table></body></html>')

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))
        return filename

    def generate_csv(self, incidents, filename=None):
        if not filename:
            filename = os.path.join(
                REPORTS_DIR,
                f"report_{datetime.now():%Y%m%d_%H%M%S}.csv")
        with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(['ID', 'Время', 'Event ID', 'Правило',
                             'Критичность', 'Описание', 'Источник', 'Статус'])
            for inc in incidents:
                writer.writerow([inc[0], inc[1], inc[2], inc[3],
                                 inc[4], inc[5], inc[6], inc[8]])
        return filename