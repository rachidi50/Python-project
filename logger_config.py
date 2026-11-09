"""Configuration centralisée des journaux avec rotation."""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(directory: str = 'logs') -> None:
    """Associer chaque module à un fichier et afficher les messages utiles."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter('%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    groups = {
        'ingestion': ['ingestion', 'adapter.ingestion'],
        'processing': ['processing', 'adapter.processing', 'adapter.geolocation'],
        'storage': ['storage'], 'serving': ['serving'],
        'main': ['__main__', 'main', 'pipeline_adapter'],
    }
    for filename, names in groups.items():
        for name in names:
            logger = logging.getLogger(name)
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
                handler.close()
            handler = RotatingFileHandler(root / f'{filename}.log', maxBytes=2_000_000,
                                          backupCount=3, encoding='utf-8')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logging.getLogger().handlers = [console]
    logging.getLogger().setLevel(logging.INFO)
