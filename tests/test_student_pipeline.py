"""Vérifications de l'adaptateur sans accès réseau."""
import gzip
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pipeline_adapter import GeoLocator, parse_event, read_lines, run_pipeline
from storage.events import EventStore


def line(message: str) -> str:
    return f'May 7 01:02:03 host sshd[42]: {message}\n'


class AdapterTests(unittest.TestCase):
    def test_repetitions_and_empty_user(self):
        event = parse_event(line('message repeated 4 times: [ Failed password for invalid user admin from 8.8.8.8 port 22 ssh2]'), 2025)
        self.assertEqual((event['status'], event['weight']), ('Invalid', 4))
        self.assertEqual(parse_event(line('Failed none for invalid user  from 8.8.8.8 port 22'), 2025)['user'], '(vide)')
        self.assertIsNone(parse_event(line('Invalid user admin from 8.8.8.8 port 22'), 2025))
        self.assertIsNone(parse_event(line('Failed password for a from nope port 22'), 2025))

    def test_multiple_files_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'auth.log.1').write_text(line('Accepted publickey for bob from 127.0.0.1 port 22'))
            with gzip.open(root / 'auth.log.2.gz', 'wt') as stream:
                stream.write(line('Failed password for invalid user a from 127.0.0.1 port 22'))
            store = EventStore(':memory:')
            for _ in range(2):
                result = run_pipeline(root, 2025, store, True)
                self.assertEqual(result['lines'], 2)
                self.assertEqual(store.aggregate('user', ('Success',)), [('bob', 1)])
            (root / 'bad.gz').write_bytes(b'not gzip')
            with self.assertRaises(OSError):
                run_pipeline(root, 2025, store, True)
            self.assertEqual(store.aggregate('user', ('Success',)), [('bob', 1)])
            store.close()

    def test_country_cache_timeout_and_local(self):
        store = EventStore(':memory:')
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return b'{"country":"US"}'
        with patch('urllib.request.urlopen', return_value=Response()) as request:
            geo = GeoLocator(store)
            self.assertEqual(geo.country('127.0.0.1'), 'Local / réservé')
            self.assertEqual(geo.country('8.8.8.8'), 'US')
            self.assertEqual(geo.country('8.8.8.8'), 'US')
            self.assertEqual(GeoLocator(store).country('8.8.8.8'), 'US')
            self.assertEqual(request.call_count, 1)
        with patch('urllib.request.urlopen', side_effect=TimeoutError) as request:
            geo = GeoLocator(store)
            self.assertEqual(geo.country('1.1.1.1'), 'Inconnu')
            self.assertEqual(geo.country('1.1.1.1'), 'Inconnu')
            self.assertEqual(request.call_count, 1)
        store.close()

    def test_strict_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.log'
            path.write_bytes(b'\xff')
            with self.assertRaises(UnicodeError):
                list(read_lines(path))


if __name__ == '__main__':
    unittest.main()
