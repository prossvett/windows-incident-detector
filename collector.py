# collector.py
# Модуль чтения событий из журналов Windows
# Использует современный API EvtQuery (pywin32), который корректно
# работает с журналами Windows 10/11 и серверными ОС.

import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from config import LOGS, MAX_EVENTS_PER_LOG


# Пространство имён XML событий Windows
NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}


class EventCollector:
    def __init__(self, logs=None, lookback_minutes=5):
        self.logs = logs or LOGS
        # С какого момента читать события при первом запуске
        self.last_check = datetime.now(timezone.utc) - timedelta(
            minutes=lookback_minutes)

    def _build_query(self):
        """Формирует XPath-запрос для EvtQuery: события после last_check."""
        # Формат времени для Windows Event Log: ISO 8601 с 'Z'
        ts = self.last_check.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return f"*[System[TimeCreated[@SystemTime >= '{ts}']]]"

    def _read_log(self, log_name):
        """Чтение событий из одного журнала через EvtQuery."""
        events = []
        query = self._build_query()
        flags = (win32evtlog.EvtQueryChannelPath |
                 win32evtlog.EvtQueryReverseDirection)
        try:
            handle = win32evtlog.EvtQuery(log_name, flags, query, None)
        except Exception as e:
            print(f"[!] Не удалось открыть журнал '{log_name}': {e}")
            return events

        while True:
            try:
                records = win32evtlog.EvtNext(handle, MAX_EVENTS_PER_LOG)
            except Exception as e:
                print(f"[!] Ошибка чтения '{log_name}': {e}")
                break
            if not records:
                break
            for record in records:
                try:
                    xml_str = win32evtlog.EvtRender(
                        record, win32evtlog.EvtRenderEventXml)
                    parsed = self._parse_xml(xml_str, log_name)
                    if parsed:
                        events.append(parsed)
                except Exception as e:
                    print(f"[!] Ошибка разбора события: {e}")
        return events

    def _parse_xml(self, xml_str, log_name):
        """Разбор XML события в словарь."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        system = root.find('e:System', NS)
        if system is None:
            return None

        event_id_el = system.find('e:EventID', NS)
        time_el = system.find('e:TimeCreated', NS)
        provider_el = system.find('e:Provider', NS)

        if event_id_el is None or time_el is None:
            return None

        event_id = int(event_id_el.text)
        time_str = time_el.attrib.get('SystemTime', '')
        # Приводим формат к "YYYY-MM-DD HH:MM:SS" (локальное время)
        try:
            dt = datetime.fromisoformat(
                time_str.replace('Z', '+00:00')).astimezone()
            time_local = dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            time_local = time_str

        provider = provider_el.attrib.get('Name', '') if provider_el is not None else ''

        # Извлекаем все Data-элементы события (полезная нагрузка)
        event_data = root.find('e:EventData', NS)
        data_values = []
        if event_data is not None:
            for data in event_data.findall('e:Data', NS):
                if data.text:
                    data_values.append(data.text)

        return {
            'log': log_name,
            'event_id': event_id,
            'time': time_local,
            'source': provider,
            'data': data_values,
            'raw': ' | '.join(data_values),
        }

    def collect_all(self):
        """Сбор событий из всех журналов."""
        all_events = []
        for log in self.logs:
            all_events.extend(self._read_log(log))
        # Обновляем метку последней проверки
        self.last_check = datetime.now(timezone.utc)
        return all_events