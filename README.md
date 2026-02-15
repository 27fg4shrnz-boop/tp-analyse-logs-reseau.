# tp-analyse-logs-reseau.
# TP : Analyseur de Logs Réseau (NOC)

Ce projet permet d'analyser des traces réseau pour détecter des comportements suspects.

## Installation et Utilisation

### Version C
1. Compilation : `gcc main.c -o log_analyzer`
2. Lancer : `./log_analyzer`

### Version Python
1. Lancer : `python3 analyzer.py`

## Fonctionnalités
- Calcul des statistiques (Total, Succès, Échecs).
- Top 3 des ports les plus utilisés.
- Détection d'IP suspectes (> 5 échecs sur un même port).
- Génération automatique d'un rapport `rapport_analyse.txt`.
Initial commit.
