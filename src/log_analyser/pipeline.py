"""Local SSH authentication analytics. No logs are sent to an external service."""
import argparse
import csv
import gzip
import ipaddress
import json
import logging
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

AUTH = re.compile(r'(?P<status>Failed|Accepted) (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')
HEADER = re.compile(r'^(?P<stamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+sshd(?:-session)?\[\d+\]:')


def extract(line, year):
    header = HEADER.match(line)
    if not header:
        return None
    auth = AUTH.match(line[header.end():].lstrip())
    if not auth:
        return None
    try:
        ip = str(ipaddress.ip_address(auth['ip']))
        stamp = header['stamp']
        date = datetime.fromisoformat(stamp.replace('Z', '+00:00')) if stamp[0].isdigit() else datetime.strptime(f'{year} {stamp}', '%Y %b %d %H:%M:%S')
    except ValueError:
        logger.warning("Invalid authentication timestamp or IP address")
        return None
    return dict(timestamp=date.isoformat(), host=header['host'], status='failed' if auth['status'] == 'Failed' else 'success', method=auth['method'], user=auth['user'], ip=ip, port=int(auth['port']), invalid_user=bool(auth['invalid']))


def ingest(path):
    path = Path(path)
    files = sorted(p for p in path.iterdir() if p.is_file() and (p.name.startswith(('auth.log', 'secure')) or p.suffix in ('.log', '.gz'))) if path.is_dir() else [path]
    if not files:
        raise ValueError(f'No log files found in {path}')
    for file in files:
        opener = gzip.open if file.suffix == '.gz' else open
        with opener(file, 'rt', encoding='utf-8', errors='replace') as stream:
            for line in stream:
                yield file.name, line


def countries_from_csv(path):
    if not path:
        return {}
    with open(path, newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {'ip', 'country'}.issubset(reader.fieldnames):
            raise ValueError('Country CSV must contain ip,country columns')
        countries = {}
        for row in reader:
            if not row.get('ip') or row.get('country') is None:
                raise ValueError(f'Country CSV row {reader.line_num}: missing ip or country')
            try:
                ip = str(ipaddress.ip_address(row['ip'].strip()))
            except ValueError as error:
                raise ValueError(f'Country CSV row {reader.line_num}: invalid IP address') from error
            countries[ip] = row['country'].strip() or 'Unknown'
        return countries


def analyse(path, year, countries=None, threshold=10, window=300):
    if not 1 <= year <= 9999:
        raise ValueError('year must be between 1 and 9999')
    if threshold < 1 or window < 1:
        raise ValueError('threshold and window must be positive')
    countries = countries or {}
    events, ignored = [], 0
    for source, line in ingest(path):
        event = extract(line, year)
        if event is None:
            ignored += 1
            continue
        address = ipaddress.ip_address(event['ip'])
        event.update(source=source, country=countries.get(event['ip'], 'Unknown') if address.is_global else 'Local / reserved')
        events.append(event)
    # Epoch values allow ISO timestamps with different offsets to sort correctly.
    def epoch(event):
        date = datetime.fromisoformat(event['timestamp'])
        return date.replace(tzinfo=date.tzinfo or timezone.utc).timestamp()
    events.sort(key=epoch)
    queues, suspicious = defaultdict(deque), set()
    peaks = defaultdict(int)
    first_burst = {}
    for event in events:
        event['success_after_burst'] = event['status'] == 'success' and event['ip'] in first_burst
        if event['status'] != 'failed':
            continue
        queue = queues[event['ip']]
        now = epoch(event)
        queue.append(now)
        while queue and now - queue[0] > window:
            queue.popleft()
        peaks[event['ip']] = max(peaks[event['ip']], len(queue))
        if len(queue) >= threshold:
            suspicious.add(event['ip'])
            first_burst.setdefault(event['ip'], event['timestamp'])
    for event in events:
        event['suspected_automation'] = event['ip'] in suspicious
        event['peak_failures_in_window'] = peaks[event['ip']]
    return dict(events=events, ignored_lines=ignored, year=year, threshold=threshold, window_seconds=window,
                summary=dict(attempts=len(events), failed=sum(e['status'] == 'failed' for e in events), success=sum(e['status'] == 'success' for e in events), unique_ips=len({e['ip'] for e in events}), suspected_ips=len(suspicious), suspected_attempts=sum(e['suspected_automation'] for e in events), successes_after_burst=sum(e['success_after_burst'] for e in events)))


def main():
    parser = argparse.ArgumentParser(description='Analyse local SSH logs and generate a dashboard.')
    parser.add_argument('--input', default='data', help='Log file or directory; plain text and gzip supported')
    parser.add_argument('--year', required=True, type=int, help='Actual year of logs with syslog timestamps (no year in source)')
    parser.add_argument('--countries', help='Optional CSV with ip,country columns')
    parser.add_argument('--output', default='output')
    parser.add_argument('--threshold', type=int, default=10)
    parser.add_argument('--window', type=int, default=300, help='Sliding detection window in seconds')
    args = parser.parse_args()
    if args.threshold < 1 or args.window < 1:
        parser.error('threshold and window must be positive')
    try:
        log_directory = Path(args.output) / 'logs'
        log_directory.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_directory / 'application.log', encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
        logging.getLogger().addHandler(handler)
    except OSError as error:
        parser.error(f'Cannot initialize application logging: {error}')
    try:
        logger.warning('Analysis started')
        result = analyse(args.input, args.year, countries_from_csv(args.countries), args.threshold, args.window)
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(result, ensure_ascii=True)
        template = Path(__file__).with_name('dashboard.html').read_text(encoding='utf-8')
        (output / 'events.json').write_text(payload, encoding='utf-8')
        (output / 'dashboard.html').write_text(template.replace('__DATA__', payload.replace('<', '\\u003c')), encoding='utf-8')
    except (OSError, ValueError, KeyError, csv.Error, EOFError) as error:
        logger.exception("Pipeline failed")
        parser.error(str(error))
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
    print(json.dumps(result['summary'], indent=2))
    print(f'Dashboard: {(output / "dashboard.html").resolve()}')
