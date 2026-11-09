"""Compatibility reader for plain-text and compressed log exports."""
import logging
import gzip
from pathlib import Path


logger = logging.getLogger(__name__)

def ingest(path: str):
    """Return lines from every file in a directory, or a single log file.

    I/O errors propagate so callers can distinguish failure from empty input.
    """
    try:
        root = Path(path)
        files = sorted(file for file in root.iterdir() if file.is_file()) if root.is_dir() else [root]
        rows = []
        for file in files:
            opener = gzip.open if file.suffix == '.gz' else open
            with opener(file, 'rt', encoding='utf-8', errors='replace') as stream:
                rows.extend(stream)
        return rows
    except (OSError, EOFError):
        logger.exception('Log ingestion failed')
        raise



if __name__ == '__main__':
    print(ingest('./data')[:10])
