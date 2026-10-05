# database.py
# Модуль работы с базой данных SQLite

import sqlite3
from config import DB_PATH


class Database:
    def __init__(self, db_path=DB_PATH):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                source TEXT,
                raw_data TEXT,
                status TEXT DEFAULT 'new'
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        self.conn.commit()

    def add_incident(self, incident):
        """Добавление одного инцидента."""
        self.cursor.execute('''
            INSERT INTO incidents
            (timestamp, event_id, rule_name, severity, description,
             source, raw_data, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident['timestamp'],
            incident['event_id'],
            incident['rule_name'],
            incident['severity'],
            incident['description'],
            incident['source'],
            incident['raw_data'],
            incident.get('status', 'new'),
        ))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_incidents(self, severity=None, limit=200):
        """Выборка инцидентов с фильтром по критичности."""
        query = "SELECT * FROM incidents"
        params = []
        if severity and severity != 'all':
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def update_status(self, incident_id, status):
        self.cursor.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (status, incident_id)
        )
        self.conn.commit()

    def get_statistics(self):
        self.cursor.execute(
            "SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
        return dict(self.cursor.fetchall())

    def close(self):
        self.conn.close()