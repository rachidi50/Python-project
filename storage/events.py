"""Stockage transactionnel des événements SSH et du cache IP."""
import logging
import sqlite3
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


class EventStore:
    """Conserver la dernière analyse et un cache indépendant des événements."""

    def __init__(self, path: str | Path) -> None:
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(path)
            self.connection.executescript('''
                CREATE TABLE IF NOT EXISTS events (
                    timestamp TEXT, ip TEXT, user TEXT, status TEXT,
                    country TEXT, source TEXT, weight INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS countries (ip TEXT PRIMARY KEY, country TEXT);
            ''')
        except (OSError, sqlite3.Error):
            logger.exception('Impossible d’ouvrir le stockage')
            raise

    def replace_events(self, events: Iterable[dict]) -> None:
        """Remplacer atomiquement l'analyse pour éviter les doublons au relancement."""
        try:
            with self.connection:
                self.connection.execute('DELETE FROM events')
                self.connection.executemany(
                    'INSERT INTO events VALUES (:timestamp,:ip,:user,:status,:country,:source,:weight)', events)
        except sqlite3.Error:
            logger.exception('Échec de stockage des événements')
            raise

    def cached_countries(self) -> dict[str, str]:
        try:
            return dict(self.connection.execute('SELECT ip,country FROM countries'))
        except sqlite3.Error:
            logger.exception('Lecture du cache impossible')
            raise

    def cache_country(self, ip: str, country: str) -> None:
        try:
            with self.connection:
                self.connection.execute('INSERT OR REPLACE INTO countries VALUES (?,?)', (ip, country))
        except sqlite3.Error:
            logger.exception('Écriture du cache impossible')
            raise

    def aggregate(self, dimension: str, statuses: tuple[str, ...], limit: int = 10) -> list[tuple[str, int]]:
        if dimension not in {'country', 'user'} or limit < 1:
            raise ValueError('Dimension ou limite invalide')
        try:
            placeholders = ','.join('?' for _ in statuses)
            return self.connection.execute(
                f'SELECT {dimension},SUM(weight) AS n FROM events WHERE status IN ({placeholders}) '
                f'GROUP BY {dimension} ORDER BY n DESC,{dimension} LIMIT ?', (*statuses, limit)).fetchall()
        except sqlite3.Error:
            logger.exception('Agrégation impossible')
            raise

    def close(self) -> None:
        self.connection.close()
