"""Trois graphiques matplotlib à partir des agrégations SQLite."""
import logging
from pathlib import Path
from storage.events import EventStore

logger = logging.getLogger(__name__)


def build_dashboard(store: EventStore, output: str | Path = 'output', top_n: int = 10,
                    show: bool = True) -> dict[str, list[tuple[str, int]]]:
    """Exporter les trois PNG et afficher leurs fenêtres si demandé."""
    if top_n < 1:
        raise ValueError('top_n doit être positif')
    import matplotlib.pyplot as plt
    figures = []
    charts = [
        ('failed_by_country', 'Tentatives échouées par pays', 'Pays',
         store.aggregate('country', ('Failed', 'Invalid'), 1_000_000)),
        ('success_by_user', 'Tentatives réussies par utilisateur', 'Utilisateur',
         store.aggregate('user', ('Success',), 1_000_000)),
        ('invalid_by_user', f'Échecs pour utilisateur invalide — top {top_n}', 'Utilisateur invalide',
         store.aggregate('user', ('Invalid',), top_n)),
    ]
    try:
        Path(output).mkdir(parents=True, exist_ok=True)
        for name, title, axis, rows in charts:
            fig, ax = plt.subplots(figsize=(10, max(4, len(rows) * 0.3)))
            figures.append(fig)
            if rows:
                labels, values = zip(*reversed(rows))
                bars = ax.barh(labels, values, color='#287c8e')
                ax.bar_label(bars, padding=3)
                ax.margins(x=0.2)
            else:
                ax.text(0.5, 0.5, 'Aucune tentative', transform=ax.transAxes, ha='center')
            ax.set_title(title)
            ax.set_xlabel('Nombre de tentatives')
            ax.set_ylabel(axis)
            fig.tight_layout()
            destination = Path(output) / f'{name}.png'
            fig.savefig(destination, dpi=150)
            logger.info('Graphique sauvegardé : %s', destination)
        if show:
            plt.show()
    except (OSError, RuntimeError, ValueError):
        logger.exception('Création ou affichage des graphiques impossible')
        raise
    finally:
        for fig in figures:
            plt.close(fig)
    return {name: rows for name, _, _, rows in charts}
