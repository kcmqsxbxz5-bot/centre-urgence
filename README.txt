
# Version Pro v7

## Nouveautés
- Vérification publique via QR Code (/verify/<id>)
- Export PDF des archives légales
- Signature numérique (hash + clé secrète)

## Utilisation
1. Archiver un dossier → génère hash + signature
2. Télécharger le rapport PDF → QR Code inclus
3. Scanner le QR → page publique de vérification

## Sécurité
Changer SIGN_KEY dans app.py pour production.
