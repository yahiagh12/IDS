# gui/__init__.py
"""
Package gui pour le projet ids_advanced.
<s
Ce package contient les modules pour l'interface graphique :
- capture_gui_adv.py : GUI pour le contrôle et la visualisation des captures réseau
"""

# Importer le module pour un accès direct via le package
from .capture_gui_adv import CaptureGUI

# Exemple d'utilisation si on exécute le package directement
if __name__ == "__main__":
    print("[INFO] Package 'gui' chargé. Utilisez CaptureGUI pour démarrer l'interface graphique.")
