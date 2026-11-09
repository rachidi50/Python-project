import gzip
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from log_analyser.pipeline import analyse, countries_from_csv, extract


class PipelineTests(unittest.TestCase):
    def test_success_after_burst_and_secure_directory_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'secure'
            path.write_text(''.join(
                f'2025-05-07T00:00:{second:02d}Z host sshd[42]: {status} password for alice from 8.8.8.8 port 22 ssh2\n'
                for second, status in [(0, 'Accepted'), (1, 'Failed'), (2, 'Failed'), (3, 'Accepted')]
            ))
            result = analyse(directory, 2025, threshold=2)
            self.assertEqual(result['summary']['successes_after_burst'], 1)
            self.assertEqual(result['summary']['suspected_attempts'], 4)
            self.assertFalse(result['events'][0]['success_after_burst'])
            self.assertTrue(result['events'][-1]['success_after_burst'])
            self.assertTrue(all(e['peak_failures_in_window'] == 2 for e in result['events']))

    def test_legacy_extraction_returns_structured_event(self):
        from processing.extract_transform import extract as legacy_extract
        event = legacy_extract('May 7 01:02:03 host sshd[42]: Accepted password for alice from 8.8.8.8 port 22', 2025)
        self.assertEqual(event['status'], 'success')
        self.assertIsNone(legacy_extract('unrelated system event', 2025))

    def test_embedded_auth_message_is_not_an_attempt(self):
        self.assertIsNone(extract('May 7 01:02:03 host sshd[42]: error: Failed password for alice from 8.8.8.8 port 22', 2025))

    def test_country_csv_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'countries.csv'
            for content in ('', 'address,name\n8.8.8.8,US\n', 'ip,country\n8.8.8.8\n', 'ip,country\nbad,US\n'):
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaises(ValueError):
                        countries_from_csv(path)
            path.write_text('ip,country\n 8.8.8.8 , US \n1.1.1.1,\n')
            self.assertEqual(countries_from_csv(path), {'8.8.8.8': 'US', '1.1.1.1': 'Unknown'})

    def test_invalid_analysis_settings(self):
        for settings in ({'year': 0}, {'year': 2025, 'threshold': 0}, {'year': 2025, 'window': 0}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                analyse('unused', **settings)

    def test_legacy_reader_reads_all_files(self):
        from ingestion.read import ingest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'auth.log').write_text('first\n')
            (root / 'subdirectory').mkdir()
            with gzip.open(root / 'auth.log.1.gz', 'wt') as stream:
                stream.write('second\n')
            self.assertEqual(ingest(root), ['first\n', 'second\n'])
            self.assertEqual(ingest(root / 'auth.log'), ['first\n'])

    def test_parse(self):
        event = extract('May  7 01:02:03 host sshd[42]: Failed password for invalid user admin from 2001:4860:4860::8888 port 22 ssh2', 2025)
        self.assertEqual(event['ip'], '2001:4860:4860::8888')
        self.assertTrue(event['invalid_user'])
        self.assertIsNone(extract('May 7 01:02:03 host CRON[1]: session opened', 2025))
        self.assertEqual(extract('2025-05-07T01:02:03+00:00 host sshd[42]: Accepted publickey for alice from 8.8.8.8 port 22 ssh2', 2024)['status'], 'success')

    def test_rotations_and_sliding_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def line(time, status='Failed'):
                return f'May 7 {time} host sshd[42]: {status} password for alice from 8.8.8.8 port 22 ssh2\n'
            (root / 'auth.log').write_text(line('00:00:00') + line('00:04:59') + 'May 7 00:04:59 host sshd[42]: pam_unix(sshd:auth): authentication failure\n')
            with gzip.open(root / 'auth.log.1.gz', 'wt') as stream:
                stream.write(line('00:05:01') + line('00:05:02', 'Accepted'))
            result = analyse(root, 2025, {'8.8.8.8': 'US'}, threshold=3)
            self.assertEqual(result['summary']['attempts'], 4)
            self.assertEqual(result['summary']['suspected_ips'], 0)
            result = analyse(root, 2025, {'8.8.8.8': 'US'}, threshold=2)
            self.assertEqual(result['summary']['suspected_ips'], 1)
            self.assertEqual(result['ignored_lines'], 1)
            self.assertEqual(result['events'][0]['country'], 'US')


if __name__ == '__main__':
    unittest.main()
