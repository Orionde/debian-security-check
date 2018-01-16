# debian-security-check
### Utilité
Génère un fichier XLM ayant pour but d'être interprété par [Spacewalk](http://spacewalk.redhat.com/)
### Installation

1) Cloner repo :
```bash
git clone https://github.com/congiohj/debian-security-check
```
2) Aller dans le repo :
```bash
cd debian-security-check
```
3) Cloner le repo svn de Debian:
```bash
# apt-get install subversion (pour svn si pas installé)
# Penser à ouvir les ports de svn : 3890 en TCP / UDP
svn co svn://anonscm.debian.org/svn/secure-testing
```

4) Installer les dépendances Python
```bash
apt-get install python-bs4
```

5) Lancer le script :
```bash
rm XML  # Supprimer l'ancien XML : ouvert en mode append
python debian-security-check.py
```

6) Nota :
> Pas de fichier de log

> Les DSA / DLA d'avant 2008 ne sont pas traitées correctement

> Le programme complète le fichier XML s'il est présent ou le crée de 0 s'il ne le trouve pas (Le fichier doit être nommé XML et se trouver à la racine du projet). Ne pas supprimer le fichier XML, sa création entière prend environ 5h
