# config.py
# Конфигурация программы выявления инцидентов безопасности Windows

DB_PATH = 'incidents.db'
RULES_PATH = 'rules.json'
REPORTS_DIR = 'reports'
CHECK_INTERVAL = 30   # интервал мониторинга в секундах

# Журналы Windows, которые программа будет читать
LOGS = [
    'Security',
    'System',
    'Microsoft-Windows-PowerShell/Operational',
]

# Максимальное количество событий, читаемых из журнала за одну итерацию
MAX_EVENTS_PER_LOG = 100