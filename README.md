# Pipeline Log Analyser

Ce projet analyse des journaux d'authentification SSH. Il lit les rotations texte et gzip, extrait les tentatives, associe un pays aux IP et construit trois graphiques. SQLite conserve la dernière analyse et le cache des pays. Aucun package supplémentaire n'a été ajouté.

## Organisation

```text
main.py                     lancement et gestion globale des erreurs
logger_config.py            journaux avec rotation
pipeline_adapter.py         lecture, regex, enrichissement et orchestration
storage/events.py           classe EventStore, SQLite et agrégations
serving/dashboard.py        fonction build_dashboard et exports PNG
ingestion/                 lecteur existant, conservé tel quel
processing/                extraction et géolocalisation existantes, conservées
src/log_analyser/           ancien pipeline et dashboard HTML, conservés
data/                       auth.log.1, auth.log.2, auth.log.3.gz, auth.log.4.gz
tests/                      tests unittest
logs/                       journaux générés, ignorés par Git
output/                     base SQLite et graphiques, ignorés par Git
```

## Installation et lancement

Depuis le dossier du projet, avec Python 3.13 ou plus récent :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests matplotlib psycopg2-binary
python main.py --year 2025
```

L'année 2025 est un exemple : il faut fournir l'année réelle des logs. Les dates syslog ne la contiennent pas. Le pipeline accepte également les dates ISO avec année et fuseau horaire.

Sans réseau ni fenêtres graphiques :

```bash
python main.py --year 2025 --offline --no-show
```

Exemple avec chemins et top personnalisés :

```bash
python main.py --input data --year 2025 --database output/events.sqlite3 --output output --log-dir logs --top 15 --no-show
python -m unittest discover -s tests -v
```

Le lancement prévu pour ce travail est `python main.py`. Le point d'entrée installé `log-analyser` de l'ancien code dans `src/` conserve son comportement antérieur.

## Lecture et extraction

Exemples de lignes prises en charge :

```text
May 24 12:00:00 ns sshd[42]: Failed password for invalid user admin from 8.8.8.8 port 22 ssh2
May 24 12:01:00 ns sshd[42]: Accepted publickey for alice from 127.0.0.1 port 22 ssh2
May 24 12:02:00 ns sshd[42]: message repeated 3 times: [ Failed password for root from 8.8.8.8 port 22 ssh2]
```

L'adaptateur ne dépend pas du code de parsing existant. Ses regex extraient la date, l'IP, l'utilisateur et le statut `Success`, `Failed` ou `Invalid`. Il valide les IP avec `ipaddress`. Un nom vide devient `(vide)`.

`Invalid` désigne une authentification échouée avec `for invalid user`. Une ligne séparée `Invalid user ...`, un message PAM ou une déconnexion ne sont pas comptés comme une autre tentative. Une répétition explicite représente N tentatives supplémentaires, stockées dans le champ `weight`.

La lecture UTF-8 est stricte. Un fichier absent, interdit, mal encodé ou gzip corrompu interrompt l'analyse avec journalisation et code de sortie 1. Les événements précédents sont conservés en cas d'échec de lecture. Le remplacement des événements est transactionnel : relancer l'analyse ne double pas les chiffres. Les fichiers présents dans le dossier d'entrée doivent tous être des logs.

## Géolocalisation

Le mode normal appelle `https://ipinfo.io/<IP>/json` avec un timeout de trois secondes. Il transmet uniquement les IP publiques, pas le contenu des logs. Les codes pays à deux lettres sont gardés en mémoire puis en SQLite. Une IP connue n'est pas redemandée aux lancements suivants. Les adresses privées, locales et réservées portent le libellé `Local / réservé`.

Un pays absent ou une erreur devient `Inconnu`. Les échecs sont mémorisés pour le lancement courant, mais pas durablement, pour permettre une nouvelle tentative au lancement suivant. Une erreur réseau, une réponse invalide ou un HTTP 401/403/429 suspend les nouveaux appels pour ce lancement et journalise la cause. Le mode `--offline` utilise le cache existant sans appeler l'API.

## Les trois graphiques

- `output/failed_by_country.png` : somme des poids `Failed` et `Invalid`, par pays, sans couper les pays au top N.
- `output/success_by_user.png` : somme des poids `Success`, par utilisateur, pour les connexions acceptées.
- `output/invalid_by_user.png` : somme des poids `Invalid` par nom, limitée au top demandé (10 par défaut).

Chaque graphique contient un titre, des axes et les valeurs. Une analyse sans tentative produit des graphiques avec le texte « Aucune tentative ». `build_dashboard()` sauvegarde les PNG puis affiche les fenêtres, sauf avec `--no-show`.

## Logging

Chaque nouveau module utilise `logging.getLogger(__name__)`. L'adaptateur distingue ses étapes avec les loggers `adapter.ingestion`, `adapter.processing` et `adapter.geolocation`. Ils écrivent dans `logs/ingestion.log` et `logs/processing.log`. Les modules SQLite, matplotlib et le point d'entrée écrivent dans `storage.log`, `serving.log` et `main.log`.

Format : `%(asctime)s|%(levelname)s|%(name)s|%(message)s`.

Chaque fichier tourne à 2 Mo, avec trois sauvegardes. Les erreurs d'E/S, d'encodage, les messages d'authentification non parsables, les IP et dates invalides, les erreurs HTTP/réseau, SQLite et matplotlib sont journalisées. Les lignes normales sans authentification sont ignorées ; leur détail est disponible au niveau DEBUG. Le bilan final est dans `logs/main.log`. Le code ajouté n'utilise pas `print`.

## Vérification sur les données fournies

Les quatre fichiers contiennent 65 565 lignes. Un comptage indépendant des messages d'authentification et de leurs répétitions donne :

- 16 361 tentatives échouées, dont 3 253 pour des utilisateurs invalides ;
- 1 tentative réussie ;
- top des utilisateurs invalides : admin 354, support 300, esisa 203, ubuntu 135, user 121, test 82, dev 70, solana 67, orangepi 60, ubnt 40.

Le test réseau réel a enrichi 997 IP, réparties dans 76 pays, avant une réponse HTTP 429 (quota ipinfo). Le pipeline a terminé normalement ; 5 528 tentatives échouées restent classées `Inconnu`. Les IP déjà enrichies restent en cache. Une reprise après rétablissement du quota peut compléter les pays manquants.

Ces chiffres ont été comparés aux agrégations SQLite. Les tests couvrent les rotations gzip, répétitions, noms vides, IP invalides, encodages invalides, cache persistant, timeout et absence de doublons après relancement. Le mode sans réseau classe les IP publiques non présentes en cache comme `Inconnu` ; il ne permet pas de valider leur pays réel.

## Workflow Git

Les changements sont enregistrés progressivement : logging, stockage, adaptateur, graphiques, tests, lancement et documentation. Les fichiers déjà dans l'index avant ce travail ne sont pas inclus par un `git add .`. L'environnement, les caches Python, les journaux et les résultats générés sont ignorés.

Aucun dépôt distant n'était configuré au démarrage. Une fois son URL connue :

```bash
git remote add origin URL_DU_DEPOT
git push -u origin master
```

## Limites connues

Les fichiers `ingestion/` et `processing/` n'ont pas été modifiés pendant ce travail. Leur contenu de travail était déjà différent du contenu préparé dans l'index Git : ces différences préexistantes ont été conservées.

Dans la version de travail actuelle :

- `ingestion/read.py` lit déjà tous les fichiers, mais charge tout en mémoire et remplace silencieusement les caractères UTF-8 invalides ; le retour prématuré cité dans le sujet concerne la version encore dans l'index.
- `processing/extract_transform.py` retourne déjà des événements, mais importe l'ancien pipeline de `src/`, qui ne pondère pas les répétitions. La version de l'index affichait le résultat au lieu de le retourner.
- `processing/geolocation.py` dispose déjà d'un timeout, mais n'a ni cache ni traitement des IP privées ; ses erreurs remontent à l'appelant. La version de l'index ne possédait pas de timeout et construisait une URL sans séparateur avant l'IP.
- Les scripts de démonstration existants contiennent encore des `print` ; ils ne sont pas exécutés par le nouvel adaptateur.

Le nouveau pipeline prépare les événements en mémoire avant stockage. Il ne déduit pas les changements d'année entre rotations. Les dates syslog sont sans fuseau horaire. Il ne déduplique pas les fichiers qui se recouvrent. Les pays dépendent de la disponibilité et des quotas d'ipinfo, et le cache n'expire pas automatiquement. L'affichage interactif exige un environnement graphique ; le mode `--no-show` permet les exports sur un serveur.

## Améliorations possibles

Ajouter une durée de validité au cache, un token ipinfo configurable, une détection du changement d'année et un chargement par lots pour les très gros volumes. Une règle documentée pourrait distinguer les fichiers qui se recouvrent des tentatives répétées légitimes.
