"""Adaptateur autonome : lecture stricte, extraction SSH et géolocalisation."""
import gzip
import ipaddress
import json
import logging
import re
import urllib.error
import urllib.request
import zlib
from datetime import datetime
from pathlib import Path
from typing import Iterator
from storage.events import EventStore

logger = logging.getLogger(__name__)
ingestion_logger = logging.getLogger('adapter.ingestion')
processing_logger = logging.getLogger('adapter.processing')
geo_logger = logging.getLogger('adapter.geolocation')
HEADER = re.compile(r'^(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+sshd(?:-session)?\[\d+\]:\s*(?P<message>.*)$')
AUTH = re.compile(r'(?P<result>Failed|Accepted) (?:password|publickey|keyboard-interactive(?:/pam)?|none) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+(?:\s|$)')
REPEATED = re.compile(r'message repeated (?P<count>\d+) times:\s*\[\s*(?P<message>.*?)\s*\]\s*$')


def read_lines(directory: str | Path) -> Iterator[tuple[str, str]]:
    """Lire tous les fichiers, y compris gzip, sans masquer les erreurs d'E/S."""
    try:
        root = Path(directory)
        files = sorted(p for p in root.iterdir() if p.is_file()) if root.is_dir() else [root]
        if not files:
            raise FileNotFoundError(f'Aucun fichier dans {root}')
        for path in files:
            ingestion_logger.info('Lecture de %s', path)
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, 'rt', encoding='utf-8', errors='strict') as stream:
                for line in stream:
                    yield path.name, line
    except (OSError, EOFError, UnicodeError, zlib.error):
        ingestion_logger.exception('Lecture des logs interrompue')
        raise


def parse_event(line: str, year: int) -> dict | None:
    """Une ligne PAM ou Invalid user seule ne représente pas un nouvel échec."""
    header = HEADER.match(line)
    if not header:
        processing_logger.debug('Ligne hors authentification SSH : %s', line.rstrip())
        if 'Failed password' in line or 'Accepted ' in line:
            processing_logger.warning('En-tête non parsable : %s', line.rstrip())
        return None
    message = header['message']
    repeated = REPEATED.fullmatch(message)
    weight = int(repeated['count']) if repeated else 1
    auth = AUTH.match(repeated['message'] if repeated else message)
    if not auth:
        if message.startswith(('Failed ', 'Accepted ', 'message repeated ')):
            processing_logger.warning('Message non parsable : %s', message)
        return None
    try:
        stamp = header['date']
        date = datetime.fromisoformat(stamp.replace('Z', '+00:00')) if stamp[0].isdigit() else datetime.strptime(f'{year} {stamp}', '%Y %b %d %H:%M:%S')
        address = str(ipaddress.ip_address(auth['ip']))
        if weight < 1:
            raise ValueError('Répétition non positive')
    except ValueError:
        processing_logger.exception('Date, IP ou répétition invalide : %s', line.rstrip())
        return None
    status = 'Success' if auth['result'] == 'Accepted' else ('Invalid' if auth['invalid'] else 'Failed')
    return dict(timestamp=date.isoformat(), ip=address, user=auth['user'] or '(vide)', status=status, weight=weight)


class GeoLocator:
    """Cache mémoire et SQLite ; les erreurs réseau restent réessayables au prochain lancement."""

    def __init__(self, store: EventStore, offline: bool = False, timeout: float = 3.0) -> None:
        self.store = store
        self.offline = offline
        self.timeout = timeout
        self.cache = store.cached_countries()
        self.network_unavailable = False

    def country(self, ip: str) -> str:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return 'Local / réservé'
        if ip in self.cache:
            return self.cache[ip]
        country = 'Inconnu'
        if not self.offline and not self.network_unavailable:
            try:
                with urllib.request.urlopen(f'https://ipinfo.io/{address}/json', timeout=self.timeout) as response:
                    if response.status != 200:
                        raise ValueError(f'HTTP {response.status}')
                    payload = json.load(response)
                if not isinstance(payload, dict):
                    raise ValueError('Réponse JSON non structurée')
                value = payload.get('country')
                if isinstance(value, str) and re.fullmatch('[A-Z]{2}', value):
                    country = value
                    self.store.cache_country(ip, country)
                else:
                    geo_logger.warning('Pays absent pour %s', ip)
            except urllib.error.HTTPError as error:
                geo_logger.error('HTTP %s pour %s', error.code, ip)
                if error.code in (401, 403, 429):
                    self.network_unavailable = True
            except (OSError, ValueError, UnicodeError):
                geo_logger.exception('Géolocalisation impossible pour %s', ip)
                self.network_unavailable = True
        self.cache[ip] = country
        return country


def run_pipeline(directory: str | Path, year: int, store: EventStore, offline: bool = False) -> dict[str, int]:
    """Préparer tous les événements avant de remplacer la dernière analyse."""
    if not 1 <= year <= 9999:
        raise ValueError('Année attendue entre 1 et 9999')
    geo = GeoLocator(store, offline)
    events = []
    counts = {'lines': 0, 'ignored': 0, 'Success': 0, 'Failed': 0, 'Invalid': 0}
    for source, line in read_lines(directory):
        counts['lines'] += 1
        event = parse_event(line, year)
        if event is None:
            counts['ignored'] += 1
            continue
        event.update(source=source, country=geo.country(event['ip']))
        events.append(event)
        counts[event['status']] += event['weight']
    store.replace_events(events)
    logger.info('Bilan : %s', counts)
    return counts
