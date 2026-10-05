# analyzer.py
# Модуль анализа событий и выявления инцидентов

import json
from datetime import datetime, timedelta
from collections import defaultdict
from config import RULES_PATH


class Analyzer:
    def __init__(self, rules_path=RULES_PATH):
        with open(rules_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)['rules']
        # Буфер для корреляции: ключ (rule_name, source) -> список datetime
        self.event_buffer = defaultdict(list)

    def _match_rule(self, event, rule):
        """Проверка соответствия события правилу."""
        if event['event_id'] != rule['event_id']:
            return False
        conditions = rule.get('conditions', {})
        if 'keywords' in conditions:
            haystack = (str(event.get('raw', '')) + ' ' +
                        str(event.get('data', ''))).lower()
            for kw in conditions['keywords']:
                if kw.lower() in haystack:
                    return True
            return False
        return True

    def analyze(self, events):
        """Применяет правила ко всем событиям, возвращает список инцидентов."""
        incidents = []
        for event in events:
            try:
                event_dt = datetime.strptime(event['time'],
                                             '%Y-%m-%d %H:%M:%S')
            except (ValueError, KeyError):
                continue

            for rule in self.rules:
                if not self._match_rule(event, rule):
                    continue

                key = (rule['name'], event.get('source', ''))
                self.event_buffer[key].append(event_dt)

                window = rule.get('time_window', 60)
                cutoff = event_dt - timedelta(seconds=window)
                self.event_buffer[key] = [
                    t for t in self.event_buffer[key] if t >= cutoff
                ]

                if len(self.event_buffer[key]) >= rule.get('threshold', 1):
                    incidents.append({
                        'timestamp': event['time'],
                        'event_id': event['event_id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'source': event.get('source', ''),
                        'raw_data': json.dumps(event, ensure_ascii=False),
                        'status': 'new',
                    })
                    self.event_buffer[key] = []
        return incidents