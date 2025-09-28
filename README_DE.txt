
WannCannaBis – Termin- und Angebots-App

## Lokaler Start (Windows)
1. Node.js installieren: https://nodejs.org/
2. ZIP entpacken.
3. `npm install` im Projektordner ausführen, um Abhängigkeiten (inkl. PostgreSQL-Treiber) zu installieren.
4. `run_windows.bat` starten **oder** `npm start` im Terminal ausführen.
5. Browser öffnen: http://localhost:3000

## Admin-Zugang
- Login: `/admin`  (Standard: `admin` / `admin1234!`)
- Schlüssel erstellen: Code + Gültigkeitstage.
- Verkäufer müssen bei Registrierung den Schlüssel angeben. Zugang läuft zum Schlüssel-Ablauf aus.

## Dauerhafter Betrieb & persistente Speicherung
Damit Eingaben auch nach langen Pausen erhalten bleiben und die Anwendung dauerhaft online erreichbar ist, sollte sie auf einem Hosting-Anbieter mit dauerhaften Diensten betrieben werden. Ein möglicher Weg ist der Einsatz von [Render](https://render.com/) mit einer angebundenen PostgreSQL-Datenbank.

### Schritte für Render
1. Repository zu GitHub hochladen oder ein öffentliches Repo nutzen.
2. Bei Render einen **Web Service** mit "Node" als Runtime anlegen und das Repository verbinden.
3. Unter "Build Command" `npm install` und unter "Start Command" `npm start` eintragen.
4. Zusätzlich in Render einen **PostgreSQL**-Dienst anlegen. Render erzeugt automatisch die Umgebungsvariable `DATABASE_URL`.
5. Auf der Service-Seite unter "Environment" die Variable `DATABASE_URL` vom Datenbank-Dienst verknüpfen (Render bietet hierfür einen Button "Add Environment Variable from Service" an).
6. Deploy starten. Beim Hochfahren initialisiert `server.js` die Tabelle `app_data` und repliziert die bestehenden Daten automatisch in die Datenbank.

Sobald die Anwendung läuft, werden alle Änderungen weiterhin lokal in `data.json` geschrieben **und** asynchron in die Datenbank übernommen. Nach einem Neustart – etwa durch ein neues Deployment – werden die Daten wieder aus PostgreSQL geladen und stehen sofort zur Verfügung.

### Hinweise für andere Hosting-Plattformen
- Wichtig ist, dass der Host die Umgebungsvariable `DATABASE_URL` bereitstellt und dauerhaft einen Node.js-Prozess laufen lässt.
- Falls kein dauerhafter Dateispeicher vorhanden ist (z. B. bei Serverless-Anbietern), stellt die PostgreSQL-Datenbank sicher, dass die Daten trotzdem nicht verloren gehen.
- Für einen 24/7-Betrieb empfiehlt sich ein Tarif ohne Sleep-Modus.
