# debian-security-check
### Utilité
Génère un fichier XLM ayant pour but d'être interprété par [Spacewalk](http://spacewalk.redhat.com/)

Le fichier XML est généré d'après les dernières DLA / DSA traitées au run précédent. Si le scrjamais run, ajouter manuellement dans last_DXA

### Installation

1) Cloner le repo git de Debian:
```bash
git clone salsa.debian.org/security-tracker-team/security-tracker.git
```

2) Installer les dépendances Python
```bash
apt update && apt install python-bs4
```

3) Lancer le script :
```bash
python3 debian-security-check.py
```

4) Nota :
> Pas de fichier de log

> Les DSA / DLA d'avant 2008 ne sont pas traitées correctement

> Le programme complète le fichier XML s'il est présent ou le crée de 0 s'il ne le trouve pas (Le fichier doit être nommé XML et se trouver à la racine du projet). Ne pas supprimer le fichier XML, sa création entière prend environ 5h
