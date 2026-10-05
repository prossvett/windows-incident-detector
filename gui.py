# gui.py
# Графический интерфейс программы

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

from collector import EventCollector
from analyzer import Analyzer
from database import Database
from reporter import Reporter
from config import CHECK_INTERVAL


class App:
    def __init__(self, root):
        self.root = root
        self.root.title(
            "Система выявления инцидентов безопасности Windows")
        self.root.geometry("1200x700")

        # Инициализация модулей
        self.db = Database()
        self.collector = EventCollector()
        self.analyzer = Analyzer()
        self.reporter = Reporter(self.db)

        self.monitoring = False
        self.monitor_thread = None

        self._build_ui()
        self.refresh_table()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- Построение интерфейса ----------
    def _build_ui(self):
        # Панель кнопок
        top = ttk.Frame(self.root)
        top.pack(fill='x', padx=10, pady=5)

        ttk.Button(top, text="▶ Запустить",
                   command=self.start_monitoring).pack(side='left', padx=2)
        ttk.Button(top, text="■ Остановить",
                   command=self.stop_monitoring).pack(side='left', padx=2)
        ttk.Button(top, text="↻ Обновить",
                   command=self.refresh_table).pack(side='left', padx=2)
        ttk.Button(top, text="Экспорт HTML",
                   command=self.export_html).pack(side='left', padx=2)
        ttk.Button(top, text="Экспорт CSV",
                   command=self.export_csv).pack(side='left', padx=2)
        ttk.Button(top, text="Статистика",
                   command=self.show_stats).pack(side='left', padx=2)

        # Фильтр
        filt = ttk.Frame(self.root)
        filt.pack(fill='x', padx=10, pady=5)
        ttk.Label(filt, text="Фильтр по критичности:").pack(side='left')
        self.filter_var = tk.StringVar(value='all')
        combo = ttk.Combobox(filt, textvariable=self.filter_var,
                             values=['all', 'critical', 'high',
                                     'medium', 'low'],
                             state='readonly', width=15)
        combo.pack(side='left', padx=5)
        combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_table())

        # Таблица
        columns = ('id', 'time', 'event_id', 'rule', 'severity',
                   'description', 'source', 'status')
        self.tree = ttk.Treeview(self.root, columns=columns,
                                 show='headings')
        headers = ['ID', 'Время', 'Event ID', 'Правило', 'Критичность',
                   'Описание', 'Источник', 'Статус']
        widths = [50, 150, 80, 150, 100, 300, 200, 90]
        for col, head, w in zip(columns, headers, widths):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=w, anchor='w')
        self.tree.pack(fill='both', expand=True, padx=10, pady=5)

        # Теги для подсветки строк по критичности
        self.tree.tag_configure('critical', background='#ffcccc')
        self.tree.tag_configure('high', background='#ffe0b3')
        self.tree.tag_configure('medium', background='#ffffcc')
        self.tree.tag_configure('low', background='#e6ffe6')

        # Статусная строка
        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(self.root, textvariable=self.status_var,
                  relief='sunken', anchor='w').pack(
            fill='x', side='bottom')

    # ---------- Работа с таблицей ----------
    def refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        incidents = self.db.get_incidents(
            severity=self.filter_var.get(), limit=200)
        for inc in incidents:
            tag = inc[4] if inc[4] in ('critical', 'high',
                                        'medium', 'low') else 'low'
            self.tree.insert('', 'end', values=(
                inc[0], inc[1], inc[2], inc[3], inc[4],
                inc[5], inc[6], inc[8]), tags=(tag,))
        self.status_var.set(
            f"Инцидентов показано: {len(incidents)} | "
            f"Мониторинг: {'активен' if self.monitoring else 'остановлен'}")

    # ---------- Мониторинг ----------
    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        self.status_var.set("Мониторинг активен")
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.status_var.set("Мониторинг остановлен")

    def _monitor_loop(self):
        while self.monitoring:
            try:
                events = self.collector.collect_all()
                incidents = self.analyzer.analyze(events)
                for inc in incidents:
                    self.db.add_incident(inc)
                if incidents:
                    # Обновляем GUI из главного потока
                    self.root.after(0, self.refresh_table)
                    self.root.after(0, lambda n=len(incidents):
                                    self.status_var.set(
                                        f"Обнаружено новых инцидентов: {n}"))
            except Exception as e:
                print(f"[!] Ошибка в цикле мониторинга: {e}")
            # Ожидание с проверкой флага
            for _ in range(CHECK_INTERVAL):
                if not self.monitoring:
                    break
                time.sleep(1)

    # ---------- Экспорт ----------
    def export_html(self):
        incidents = self.db.get_incidents(limit=1000)
        if not incidents:
            messagebox.showinfo("Экспорт", "Нет инцидентов для экспорта.")
            return
        filename = self.reporter.generate_html(incidents)
        messagebox.showinfo("Экспорт", f"HTML-отчёт сохранён:\n{filename}")

    def export_csv(self):
        incidents = self.db.get_incidents(limit=1000)
        if not incidents:
            messagebox.showinfo("Экспорт", "Нет инцидентов для экспорта.")
            return
        filename = self.reporter.generate_csv(incidents)
        messagebox.showinfo("Экспорт", f"CSV-отчёт сохранён:\n{filename}")

    def show_stats(self):
        stats = self.db.get_statistics()
        if not stats:
            messagebox.showinfo("Статистика", "Инцидентов пока нет.")
            return
        text = "Статистика по критичности:\n\n"
        for sev in ('critical', 'high', 'medium', 'low'):
            text += f"  {sev}: {stats.get(sev, 0)}\n"
        messagebox.showinfo("Статистика", text)

    # ---------- Завершение ----------
    def _on_close(self):
        self.monitoring = False
        self.db.close()
        self.root.destroy()