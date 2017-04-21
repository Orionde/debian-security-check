# debian-security-check

Installation

1) Cloner repo : git clone https://github.com/congiohj/debian-security-check
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

