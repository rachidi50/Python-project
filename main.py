"""Point d'entrée du pipeline étudiant SSH."""
import argparse
import logging
from pathlib import Path
from logger_config import configure_logging
from pipeline_adapter import run_pipeline
from serving.dashboard import build_dashboard
from storage.events import EventStore

logger = logging.getLogger(__name__)
LOG_YEAR = 2025


def main() -> int:
    parser = argparse.ArgumentParser(description='Analyser les logs SSH et générer trois graphiques.')
    parser.add_argument('--input', default='data')
    parser.add_argument('--year', type=int, default=LOG_YEAR, help='Année des logs syslog, absente des lignes (défaut : %(default)s)')
    parser.add_argument('--output', default='output')
    parser.add_argument('--database', default='output/events.sqlite3')
    parser.add_argument('--log-dir', default='logs')
    parser.add_argument('--top', type=int, default=10)
    parser.add_argument('--offline', action='store_true', help='Utiliser seulement le cache de pays')
    parser.add_argument('--no-show', action='store_true', help='Sauvegarder sans ouvrir les fenêtres')
    args = parser.parse_args()
    if not 1 <= args.year <= 9999 or args.top < 1:
        parser.error('Année entre 1 et 9999 et top strictement positif requis')
    store = None
    try:
        configure_logging(args.log_dir)
        if args.no_show:
            import matplotlib
            matplotlib.use('Agg')
        store = EventStore(args.database)
        counts = run_pipeline(args.input, args.year, store, args.offline)
        charts = build_dashboard(store, args.output, args.top, not args.no_show)
        assert sum(n for _, n in charts['failed_by_country']) == counts['Failed'] + counts['Invalid']
        assert sum(n for _, n in charts['success_by_user']) == counts['Success']
        logger.info('Analyse terminée : %s ; graphiques : %s', counts, Path(args.output).resolve())
        return 0
    except KeyboardInterrupt:
        logger.info('Analyse interrompue par l’utilisateur')
        return 130
    except Exception:
        logger.exception('Échec du pipeline')
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == '__main__':
    raise SystemExit(main())
