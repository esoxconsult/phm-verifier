# Verifikation eines Siegel-Pakets durch Dritte

> Auszug fuer das oeffentliche Pruef-Repository, erzeugt aus `docs/VERIFIKATION.md` des
> Hauptrepositorys. Pfade sind auf dieses Repository umgeschrieben. Verweise
> mit dem Zusatz "(nicht oeffentlich)" und Vorgangsnummern wie #146 beziehen
> sich auf das Hauptrepository und sind hier nicht einsehbar.

Diese Anleitung richtet sich an Pruefer, Wirtschaftspruefer, Gutachter und
Gerichte, die ein von PHM exportiertes Aufzeichnungspaket unabhaengig pruefen
wollen. Sie brauchen dafuer weder Zugang zu unseren Systemen noch unser
Mitwirken, und Sie muessen uns nichts glauben: alles Pruefbare liegt im Paket
selbst, im veroeffentlichten oeffentlichen Schluessel und in oeffentlich
pruefbaren Zertifikaten.

Technische Formate, falls Sie tiefer einsteigen wollen:
SIEGEL_UMSCHLAG.md (nicht oeffentlich) (der Umschlag um die Aufzeichnung),
SIEGEL_VERSIEGELUNG.md (nicht oeffentlich) (Siegel und Siegel-Baum),
SIEGEL_ANKER.md (nicht oeffentlich) (der externe Zeitstempel).

Dieselbe eine Verifier-Datei prueft drei Eingaben: das **Siegel-Paket**
(unten), den **Archiv-Zugehoerigkeitsnachweis** (zweiter Fall) und einen
**Abzug des oeffentlichen Wurzelverzeichnisses** (dritter Fall, dazu das
**Konsistenz-Paket**, mit dem Beobachter Staende untereinander
weitergeben). Der Typ wird an der Eingabe erkannt, es gibt keinen Schalter
dafuer.

## Was Sie in der Hand haben

Sie erhalten eine **BagIt-Ablage** (RFC 8493): ein Verzeichnis, zum
Beispiel `siegel_akte_abc123/`, mit `bagit.txt`, `manifest-sha256.txt`
und den Nutzdaten unter `data/`. BagIt ist ein offener Standard fuer
Archiv-Uebergaben; **die Prueffsummen kontrollieren Sie mit vorhandenen
Werkzeugen, ganz ohne unser Pruefskript:**

```
cd siegel_akte_abc123
shasum -a 256 --check manifest-sha256.txt
shasum -a 256 --check tagmanifest-sha256.txt
```

Unser Pruefskript ist der bequeme Weg, nicht der einzige.

Unter `data/` liegt das Siegel-Paket als JSON-Datei (zum Beispiel
`data/siegel_paket_abc123.json`) sowie, wenn mitgeliefert, der Inhalt der
Aufzeichnung als eigene Datei (`data/response.json`). Im Paket liegen:

- die **Aufzeichnung** (der "Umschlag" mit Betreff, Zeitpunkt, Methode und
  dem Fingerabdruck des Inhalts, sowie, wenn mitgeliefert, der Inhalt selbst),
- das **Siegel** darueber (eine digitale Signatur, Verfahren Ed25519, ueber
  Aufzeichnung, Zeitpunkt, Baum-Position und Vorgeschichte),
- der **oeffentliche Schluessel** der siegelnden Instanz (das Pruefmittel;
  gleichen Sie ihn gegen die veroeffentlichte Schluesselhistorie ab),
- der **Siegel-Baum** der Instanz (jedes Siegel signiert seine Position und
  die Wurzel ueber alle Vorgaenger; ein entferntes oder umsortiertes Siegel
  faellt auf),
- der **Zugehoerigkeitsnachweis** (ein Merkle-Pfad: das einzelne Siegel
  laesst sich zur Baum-Wurzel fuehren, ohne dass der uebrige Bestand
  offengelegt werden muss),
- die **Zeitstempel-Token** externer Zeitstempelstellen (RFC 3161), wenn
  das Siegel bereits verankert wurde. Das Format traegt je Siegel mehrere
  Anker (vorgesehen: ein qualifizierter Dienst und ein freier Zweitanker
  parallel, ein Angreifer muesste beide brechen). Gepinnt ist in diesem
  Repository nur das Zertifikat von freetsa.org; das Token einer anderen
  Stelle faellt in Schritt 4b, bis deren Zertifikat hier ergaenzt ist.
  Dazu gegebenenfalls Kettenkopf-Erneuerungen (`zweck` am Anker).

## Was Sie brauchen

1. Die Paketdatei.
2. Das Pruefskript `phm_verifier.py` (eine einzelne Datei; sie liegt diesem
   Repository im Wurzelverzeichnis bei und wird mit dem Paket uebergeben).
3. Python 3.8 oder neuer. Keine Zusatzpakete, keine Installation, kein
   Internet: das Skript nutzt nur die Python-Standardbibliothek und
   spricht mit niemandem.
4. Empfohlen: die **veroeffentlichte Schluesselhistorie**
   (`keys/seal_key_history.json` im Repository) als Ganzes, mit
   `--key-history`. Das Skript loest die `key_id` aus dem Siegel darin auf
   und prueft das Gueltigkeitsfenster (Schritt 3c).

   Mit `--public-key` koennen Sie stattdessen einen einzelnen Schluessel
   vorlegen. Das prueft weniger, und seit #150 sagt das Ergebnis das auch:
   der Verifier kann nicht sehen, ob Sie diesen Schluessel der Historie oder
   dem vorgelegten Paket entnommen haben. **Wer mit einem eigenen
   Schluesselpaar siegelt, legt eben seinen eigenen vor.** Das vierte Merkmal
   der Feststellungsliste ist deshalb nur mit `--key-history` erfuellbar.
5. Optional, empfohlen: das Zertifikat der Zeitstempelstelle aus einer
   Quelle, der SIE vertrauen (zum Beispiel von der Website des Anbieters).
   Damit pruefen Sie, dass der Zeitstempel wirklich von dieser Stelle stammt.

## Die Pruefung

```
python3 phm_verifier.py siegel_akte_abc123 \
    --key-history seal_key_history.json \
    --tsa-cert tsa_zertifikat.pem
```

Als Eingabe nimmt das Skript die BagIt-Ablage (Verzeichnis) oder direkt
die nackte Paketdatei (JSON). Es fuehrt die Pruefschritte aus und
begruendet jedes Ergebnis:

0. **BagIt-Ablage:** jede im Manifest genannte Prueffsumme wird
   nachgerechnet und die Vollstaendigkeit geprueft (eine eingeschmuggelte
   oder veraenderte Datei faellt auf) - unter `data/` gegen
   `manifest-sha256.txt` und in der **Bag-Wurzel** gegen
   `tagmanifest-sha256.txt`. Ausgenommen ist dort genau eine Datei: das
   Tagmanifest selbst, das seine eigene Prueffsumme nicht fuehren kann.
   Fehlt das Tagmanifest (nach RFC 8493 ist es optional), ist die Wurzel
   durch nichts gedeckt; dann zaehlt der Befundtext die ungedeckten Dateien
   auf, statt die Grenze zu verschweigen. **Jeder symbolische Verweis** in
   der Ablage, Datei oder Ordner, unter `data/` wie in der Wurzel, ist ein
   Befund mit Pfad und Ziel (#352): er wird weder verfolgt (sein Ziel kann
   ausserhalb der Ablage liegen) noch still uebersprungen, und Nutzdaten
   werden durch ihn nicht gelesen. Ausnahme, im Befund benannt: liegt eine
   der Tag-Dateien, die der Schritt zum Oeffnen braucht (`bagit.txt`,
   `manifest-sha256.txt`, `tagmanifest-sha256.txt`, `bag-info.txt`), als
   Verweis vor, wird sie trotzdem gelesen. Ebenso wird ein Manifest-Pfad, der aus der Ablage
   herausfuehrt (`..`, absolut), nicht gelesen, sondern gemeldet. Bei
   Eingabe der nackten Paketdatei wird der Schritt offen als uebersprungen
   ausgewiesen.
0b. **Angaben der Bag-Wurzel:** `bag-info.txt` liegt ausserhalb von `data/`
   und damit ausserhalb der Auslieferungsliste, traegt aber Inhalt -
   `PHM-Stichtag` ist die Aussage, auf die sich die ganze Akte bezieht. Jedes
   `PHM-`Feld dort ist die Kopie eines Wertes aus dem versiegelten Umschlag
   und wird dagegen gehalten. Ein `PHM-`Feld ohne versiegelte Entsprechung
   ist ein Befund.
1. **Umschlag:** die Aufzeichnung wird nach festen, dokumentierten Regeln
   byte-genau nachgebaut und ihr SHA-256-Fingerabdruck nachgerechnet. Liegt
   der Inhalt (Payload) bei, wird auch sein Fingerabdruck nachgerechnet.
   Jede nachtraegliche Aenderung an einem einzigen Zeichen faellt hier auf.
1a. **Inhaltsdatei:** liegt neben dem Paket die Datei, unter deren Namen der
   versiegelte Umschlag die Nutzlast fuehrt (letztes Glied von
   `payload.reference`, etwa `KRITERIENWERK.md` oder `akte.json`), wird sie
   Byte fuer Byte gegen die Nutzlast gehalten: gegen `payload.sha256` im
   Umschlag und gegen `payload_b64`. Abweichung ist ein Fehlschlag. In einer
   Ablage wird JEDE Datei unter `data/` gehalten, deren Name dem aus dem
   Umschlag entspricht, Gross-/Kleinschreibung egal, in jedem Unterordner;
   und traegt das Paket `payload_b64`, MUSS die Datei unter `data/<name>`
   liegen (dort legt jeder Erzeuger sie ab): fehlt sie oder heisst sie anders,
   ist das ein Fehlschlag. Liegt die Paketdatei selbst nicht direkt unter
   `data/`, faellt Schritt 0. Bei der nackten Paketdatei wird nur im selben
   Verzeichnis gesucht; fehlt die Datei dort, ist der Schritt uebersprungen
   mit "NICHT GEMESSEN, Datei fehlt", und die Feststellungsliste fuehrt das
   fuenfte Merkmal "gelieferte Inhaltsdatei gegen die versiegelte Nutzlast
   gehalten" als offen. Bis Oktober 2026 gab es diesen Schritt nicht: gesiegelt war nur
   `payload_b64`, die Datei, die ein Leser liest, pruefte niemand, und ein
   geaenderter Text mit nachgerechneten Manifesten bestand (Gate-A-Generalprobe
   03.10.2026, S2a/S2b; rotes Team 01, A5a). Ein Verifier, der keinen Schritt
   1a ausgibt, hat diese Luecke.
1b. **Auslieferung:** jede neben dem Paket gelieferte Datei wird gegen die
   MITVERSIEGELTE Liste im Umschlag gehalten. Veraendert, fehlend und
   zusaetzlich sind drei verschiedene Befunde, und alle drei sind Fehler.
   Fuehrt der Umschlag keine Liste, wird der Schritt uebersprungen - mit der
   Begruendung, dass die gelieferten Dateien dann nicht gedeckt sind, nie
   still gruen. Diese Dateien werden dann mit Namen aufgezaehlt, im Befund
   und im Gesamturteil (Ergebnisfeld `ungedeckte_dateien`); ausgenommen sind
   nur die Paketdatei, die Inhaltsdatei (1a), was die nachgelagerte Liste
   fuehrt (1c) und der Archiv-Nachweis (1d). In der Referenzakte steht dort
   zuerst `data/AKTE.md`: eine aus `akte.json` gerenderte Darstellung, nicht
   Teil der Nutzlast und ohne Liste nicht gesiegelt.
1c. **Nachgelagerte Liste:** was erst NACH dem Siegeln entsteht (der
   Archiv-Zugehoerigkeitsnachweis), kann in der versiegelten Liste nicht
   stehen. Dafuer gibt es `data/nachtrag.json`, eine zweite, vom Erzeuger
   signierte Liste. Sie ist **vom Siegel nicht gedeckt** und behauptet das
   auch nicht: sie bindet die Dateien an den Erzeuger und an dieses
   Siegelpaket, ihre Zeitangabe bezeugt niemand ausser uns. Nur was sie
   fuehrt, nimmt Schritt 1b aus; fehlt sie, faellt die Datei dort als
   zusaetzlich auf.
1d. **Archiv-Zugehoerigkeitsnachweis:** liegt `data/archiv_nachweis.json`
   bei, wird er hier auch inhaltlich geprueft - und daraufhin, ob er von
   DIESEM Paket handelt. Ein in sich gueltiger Nachweis ueber ein fremdes
   Dokument belegt fuer dieses hier nichts.
2. **Siegel:** aus den Siegel-Feldern und der Signatur wird der Siegel-Hash
   (`seal_hash`) neu berechnet. Dem im Paket behaupteten Wert wird an keiner
   Stelle geglaubt.
3. **Signatur (Ed25519):** die digitale Signatur des Siegels wird gegen den
   oeffentlichen Schluessel verifiziert. Legen Sie ihn mit `--public-key`
   selbst vor; ohne Vorlage nimmt das Skript den Schluessel aus dem Paket
   und weist offen aus, dass dessen Herkunft dann nicht unabhaengig belegt
   ist. Schritt 3b haelt beide gegeneinander, wenn beides vorliegt. Anders
   als bei einem symmetrischen Verfahren brauchen Sie KEIN Geheimnis, und
   der Schluessel, mit dem Sie pruefen, taugt nicht zum Faelschen.
3c. **Schluessel gegen die Historie:** mit `--key-history` wird die `key_id`
   aus dem Siegel in der veroeffentlichten Historie aufgeloest und ihr
   Gueltigkeitsfenster geprueft. Erst das bindet die Urheberschaft an eine
   Quelle AUSSERHALB des Pakets. Ohne diesen Schritt ist nur belegt, DASS
   die Signatur zu einem Schluessel passt, nicht WELCHER er ist - wer mit
   eigenem Schluesselpaar siegelt, besteht alles davor.
4. **Zeitstempel:** JEDES RFC-3161-Token im Paket wird vollstaendig
   geprueft (bei mehreren Ankern als Schritte 4.1, 4.2, ...): es muss
   genau den neu berechneten Siegel-Hash bezeugen, und die Signatur der
   Zeitstempelstelle ueber dem Token wird kryptographisch verifiziert
   (inklusive der signierten Attribute und der Bindung an das
   Signer-Zertifikat). Mit `--tsa-cert` (mehrfach angebbar, je Dienst
   eines) wird das im Token mitgefuehrte Zertifikat zusaetzlich byte-genau
   gegen Ihre Vertrauenszertifikate gehalten. Legen Sie dafuer das
   **Signer**-Zertifikat des Dienstes vor (bei freetsa.org `tsa.crt`), nicht
   die Wurzel darueber (`cacert.pem`): der Schritt vergleicht Bytes, er baut
   keine Zertifikatskette. Mit der Wurzel faellt 4b - richtigerweise, denn
   sie ist nicht das Zertifikat, das signiert hat.
5. **Baum:** jedes Blatt wird neu berechnet; geprueft werden die Blatt-Folge,
   die von jedem Siegel signierte Wurzel ueber seine Vorgaenger und dass das
   vorgelegte Siegel an genau der Position steht, die es selbst signiert hat.
6. **Zugehoerigkeitsnachweis:** das nachgerechnete Siegel wird ueber den
   mitgelieferten Merkle-Pfad zur angegebenen Wurzel gefuehrt. Das
   funktioniert auch, wenn der volle Baum nicht im Paket liegt; das Skript
   sagt dann offen, dass die Wurzel selbst in diesem Paket nicht unabhaengig
   belegt ist.

Am Ende steht ein Gesamturteil und der Exit-Code: `0` = alle durchgefuehrten
Pruefungen bestanden, `1` = mindestens eine nicht bestanden, `2` = das Paket
war nicht lesbar. Mit `--json` erhalten Sie das Ergebnis maschinenlesbar.

**Versionsbewusstsein:** die Formate sind versioniert (Umschlag-Version,
Siegel-Version), die kanonische Serialisierung ist je Version
implementiert, und das Ergebnis weist aus, gegen welche Version geprueft
wurde (Zeile "Versionen:" im Klartext, Felder `envelope_version`/
`seal_version` im JSON). Ein Siegel auf einer aelteren Format-Version
bleibt auch nach Einfuehrung neuerer Versionen pruefbar; neue Felder
entwerten alte Siegel nicht.

## Was ein bestandenes Urteil bedeutet, und was nicht

Ein bestandenes Paket belegt vier Dinge:

- **Existenz:** die Aufzeichnung existierte spaetestens zu dem Zeitpunkt, den
  die externe Zeitstempelstelle im Token bezeugt (`genTime`).
- **Unveraendertheit:** die Aufzeichnung ist seit der Versiegelung nicht
  veraendert worden, nicht um ein Zeichen.
- **Urheberschaft:** das Siegel wurde mit dem geheimen Gegenstueck des
  gepruefen oeffentlichen Schluessels erzeugt - von der Instanz, deren
  Schluesselhistorie diesen Schluessel fuehrt.
- **Position:** das Siegel steht an einer festen, von ihm selbst signierten
  Position im Siegel-Baum der Instanz.

Ausdruecklich NICHT belegt ist die **inhaltliche Richtigkeit** der
aufgezeichneten Werte. Das Siegel beweist, WAS aufgezeichnet wurde und WANN,
nicht, dass es stimmt.

## Ehrliche Grenzen

- **Der Schluesselinhaber kann neue Siegel erzeugen:** die Signatur beweist,
  dass das Siegel von der Instanz stammt und unveraendert ist - nicht, dass
  die Instanz ihre eigene Historie nie neu geschrieben hat. Dagegen steht
  der externe Zeitstempel (Schritt 4): ein einmal verankertes Siegel laesst
  sich nicht rueckdatiert ersetzen. Halten Sie den oeffentlichen Schluessel
  deshalb gegen die veroeffentlichte Schluesselhistorie, nicht nur gegen
  das Paket.
- **Die Schluesselhistorie ist weder signiert noch verankert.** `--key-history`
  liest eine gewoehnliche JSON-Datei; geprueft werden Schema und doppelte
  `key_id`, sonst nichts. Wer einen Abzug ausliefert, kann eine dazu passende
  Historie mitliefern, und die Schluesselschritte werden gruen, weil sie gegen
  genau diese Datei pruefen. **Beziehen Sie die Historie deshalb aus einer
  Quelle ausserhalb des Vorgelegten** (`keys/*_key_history.json` im
  veroeffentlichten Repo) und bewahren Sie mit `--anheften` Ihren eigenen Stand
  auf: seit #146 haelt V5 die `key_id` und den `public_key` aus Ihrem Pin gegen
  den heutigen Abzug, und ein unerklaerter Wechsel ist ein Bruch. Was das
  leistet und was nicht, steht in `docs/VERZEICHNIS.md`.
- **Zertifikatskette und Sperrstatus:** das Skript prueft die Signatur der
  Zeitstempelstelle und haelt deren Zertifikat gegen das von Ihnen vorgelegte
  Vertrauenszertifikat. Ob dieses Zertifikat zu einer Wurzel fuehrt, der Sie
  vertrauen, und ob es gesperrt wurde, pruefen Sie mit Ihren
  PKI-Werkzeugen. Unabhaengige Gegenprobe mit OpenSSL (das Token liegt
  Base64-kodiert je Anker im Feld `anchors[i].token_b64`):

  ```
  python3 -c "import json,base64,sys; p=json.load(open(sys.argv[1])); open('token.der','wb').write(base64.b64decode(p['anchors'][0]['token_b64']))" siegel_paket_abc123.json
  openssl ts -reply -token_in -in token.der -text
  openssl ts -verify -digest <seal_hash> -token_in -in token.der -CAfile wurzel.pem -untrusted tsa_zertifikat.pem
  ```

  Den `<seal_hash>` nennt Ihnen das Pruefskript in Schritt 2 (der neu
  berechnete Wert); `wurzel.pem` und `tsa_zertifikat.pem` beziehen Sie von
  der Zeitstempelstelle.
- **Fehlt etwas im Paket** (kein Umschlag, kein Anker, kein Baum, kein
  oeffentlicher Schluessel), weist das Skript den betroffenen Schritt als
  uebersprungen aus und das Gesamturteil behauptet entsprechend weniger.
  Ein Paket ohne Anker traegt keine unabhaengige Zeit-Beglaubigung; ein
  Paket ohne Umschlag belegt nur Siegel, Baum und Zeitstempel, nicht den
  Inhalt.

## Paket erzeugen (auf PHM-Seite)

*Ausgelassen: der Abschnitt beschreibt den Ablauf auf Herausgeberseite und
steht nur im Hauptrepository (nicht oeffentlich).*

## Derselbe Weg fuer unsere eigenen Texte

Dasselbe Paketformat und derselbe Pruefweg gelten fuer die Fassungen
unseres Kriterienwerks: der Massstab fuer integre Aufzeichnung liegt selbst
als integre Aufzeichnung vor, versiegelt, verankert und mit diesem Verifier
im selben Paket, je Fassung eines
(`werk/kriterienwerk-v0.3/` (nicht oeffentlich),
`werk/kriterienwerk-v0.4/` (nicht oeffentlich)).
Verifier, oeffentlicher Schluessel und Anleitung liegen dabei **im Bag**, also
unter `data/`, und stehen damit in `manifest-sha256.txt`: geprueft wird mit
`python3 data/phm_verifier.py .` aus dem Bag heraus, und die beiden
`shasum`-Zeilen davor decken das Pruefwerkzeug mit ab - **beide**, denn wer
Werkzeug und `manifest-sha256.txt` zusammen umschreibt, kommt an der ersten
allein vorbei (#165). Wie weit diese Deckung reicht, sagt die Anleitung im
Paket selbst: kryptografisch gebunden ist ueber Siegel und Anker nur der
Text, das Tagmanifest ist unsigniert, und die Aussage, die ueber das Paket
hinaus traegt, ist der Abgleich von `data/phm_verifier.py` gegen
`phm_verifier.py` aus dem Repo.
Verfahren, ausgefuehrte Pruefungen und Grenzen:
WERK_VERANKERUNG.md (nicht oeffentlich). Unterschied zur Belegakte: der
Payload ist ein Text statt einer Analyse-Antwort, und gesiegelt wird mit
einem **eigenen Schluessel** (`key_id`-Raum `wk-`, Historie
[`werk_key_history.json`](../keys/werk_key_history.json)), der
niemals Kundenakten siegelt.

## Zweiter Fall: Zugehoerigkeit eines Dokuments zum Archivbestand

Dieselbe Verifier-Datei prueft einen zweiten Eingabetyp: den
**Archiv-Zugehoerigkeitsnachweis**. Er beantwortet eine andere Frage als
die Belegakte. Die Belegakte belegt eine Aufzeichnung; der Nachweis
belegt, dass **ein bestimmtes Dokument** zu einem Bestand gehoerte, der
zu einem bezeugten Zeitpunkt so und nicht anders bestand.

Sie erhalten dafuer eine einzelne JSON-Datei (`package_type:
"phm-archiv-nachweis"`) und, wenn es um eine konkrete Datei geht, das
Dokument selbst. In der Datei steht: **die eine Index-Zeile** des
Eintrags, der Merkle-Pfad zur Wurzel, das signierte Wochen-Manifest und
dessen Zeitstempel-Token. Die Dokumente anderer sind darin nicht
enthalten, und zwar nicht als Zusage, sondern nachsehbar: der Pfad
besteht aus Knoten-Hashes (SHA-256 ueber Blatt- bzw. Knoten-Bytes nach
RFC 6962), aus denen sich nichts zurueckrechnen laesst.

```
python3 phm_verifier.py nachweis.json --dokument mein_bericht.zip \
        --key-history archiv_manifest_key_history.json \
        --tsa-cert tsa_zertifikat.pem
```

**Legen Sie die Historie vor, nicht einen einzelnen Schluessel.** Die
Datei `archiv_manifest_key_history.json` fuehrt mehrere Eintraege: der
produktive Schluessel signiert die Manifeste des Produktivbestandes, der
Demo-Schluessel das Manifest der Referenzakte. Ein einzelner
`--public-key` kann diese nicht beide pruefen - er passt zu einem
Manifest und laesst das andere durchfallen, und nach der naechsten
Rotation zu keinem von beiden. Mit `--key-history` loest der Verifier den
Schluessel je Manifest ueber die `key_id` auf und prueft zusaetzlich das
Gueltigkeitsfenster. `--public-key` bleibt zulaessig, wenn Sie genau ein
Manifest gegen genau einen Schluessel halten wollen.

Der Typ wird an der Datei erkannt, es gibt keinen zusaetzlichen Schalter.
**Eine Option, die der erkannte Typ nicht auswertet, ist ein Abbruch mit
Exit-Code 2** - der Verifier nimmt sie nicht schweigend entgegen, denn
sonst laege ein Ergebnis vor, das ohne Ihre Angabe entstanden ist, und
niemand saehe es ihm an. (Das Konsistenz-Paket etwa wertet heute keinen
Schluessel aus; `--key-history` bricht dort deshalb ab, statt zu
schweigen.)

Geprueft wird:

| Schritt | Was |
|---|---|
| A1 | SHA-256 ueber die rohen Bytes der Index-Zeile = Blatt-Eingabe. Ohne unser Skript: `shasum -a 256` ueber die Zeile. |
| A1b | Mit `--dokument`: SHA-256 Ihrer Datei gegen die Prueffsumme IN der Index-Zeile. Erst das bindet die Datei an den Eintrag. |
| A2 | Der Merkle-Pfad fuehrt vom Blatt zur genannten Wurzel (RFC 6962). |
| A3 | Das Wochen-Manifest ueber dieser Wurzel: Ed25519-Signatur, `manifest_hash`, `key_id` im Raum `am-`. Mit `--key-history` wird der Schluessel je Manifest ueber die `key_id` aufgeloest, samt Gueltigkeitsfenster - dieselbe Aufloesung wie fuer die Verzeichnis-Koepfe. Mit `--public-key` gegen den einen Schluessel, den SIE vorlegen. Ohne beides bezeugt sich das Paket in diesem Punkt selbst, und der Befund sagt das. |
| A4 | Der RFC-3161-Zeitstempel auf die Wurzel, volle CMS-Pruefung wie in Schritt 4. Ohne Anker: uebersprungen, und das Urteil behauptet dann keinen Zeitpunkt. |
| A5 | Datensparsamkeit: nur die eigene Zeile und Knoten-Hashes; unbekannte Felder sind ein Befund, weil sie ein Kanal waeren. |

Exit-Code und Ausgabe folgen derselben Logik wie oben (0 bestanden,
1 nicht bestanden, 2 Datei unbrauchbar). Der Schluessel des
Archiv-Manifests ist ein **anderer** als der der Belegakten-Siegel:
`am-...` statt `ba-...`, eigene Historie
(`keys/archiv_manifest_key_history.json`). Eine Verwechslung
faellt schon an der Kennung auf, nicht erst an der Signatur.

**Was auch dieser Nachweis nicht zeigt:** dass der Bestand vollstaendig
ist. Er belegt, dass Ihr Dokument zu dem bezeugten Bestand gehoerte, und
dass an diesem Bestand seither nichts geaendert wurde. Ob jemand ein
anderes Dokument von vornherein nicht aufgenommen hat, kann er nicht
zeigen (siehe ARCHIV.md (nicht oeffentlich), Abschnitt "Was die Verankerung
NICHT beweist: Vollstaendigkeit"). Einen Teil davon deckt der dritte Fall
unten ab: dass wir nicht verschiedenen Lesern verschiedene Bestaende
zeigen.

Erzeugt wird der Nachweis auf Herausgeberseite, mit einem Werkzeug des
Hauptrepositorys (nicht oeffentlich).

## Dritter Fall: das oeffentliche Verzeichnis der Wurzeln beobachten

Der dritte Eingabetyp ist kein Nachweis, sondern ein **Abzug des
oeffentlichen Verzeichnisses** (Ordner mit `verzeichnis.jsonl`,
`koepfe/`, `anker/`). Er beantwortet die Frage, die keiner der beiden
ersten Faelle beantworten kann: **sehen alle denselben Bestand, und
bleibt der veroeffentlichte Bestand, was er war?**

```
python3 phm_verifier.py ./verzeichnis-abzug --pin angehefteter_stand.json \
        --anheften angehefteter_stand.json \
        --key-history archiv_manifest_key_history.json
```

Geprueft wird V1 bis V7 (Zeilenkette, veroeffentlichte Manifeste, deren
Anker, die Kopf-Kette, die Vertraeglichkeit mit Ihrem angehefteten Stand,
Datensparsamkeit, externe Anker auf die Koepfe selbst). V3 und V7 halten dabei
das behauptete `created_at` gegen die vom Token bezeugte Zeit: liegt die
Behauptung deutlich davor, steht das als **Befund** im Bericht (der
Nachhol-Fall sieht genauso aus wie eine Rueckdatierung); liegt sie danach, ist
es ein **Fehlschlag**. Was der Anker leistet und was nicht, steht in
`docs/VERZEICHNIS.md`. Legen Sie die
veroeffentlichte Schluesselhistorie mit `--key-history` vor, nicht einen
einzelnen `--public-key`: der Schluessel wird dann **je Manifest und je Kopf**
ueber seine `key_id` aufgeloest, das Gueltigkeitsfenster geprueft und ein
Schluesselwechsel muss erklaert sein. Ein einzelner Schluessel scheitert an
der ersten Rotation, weil aeltere Manifeste und Koepfe die alte `key_id`
tragen. **Geben Sie beides an, hat die Historie Vorrang und `--public-key`
wird nicht zusaetzlich angewandt** - konjunktiv gaebe es ueber einem
rotierten Abzug garantiert einen Befund, der in Wahrheit an Ihrer
Kommandozeile stuende und nicht am Gegenstand. Das Werkzeug sagt es beim
Aufruf, und der Bericht weist es in V2 und V4 aus. Der Sinn liegt in **V5**: erst der Vergleich mit dem,
was Sie frueher gesehen haben, macht aus dem Verzeichnis eine Aussage.
Ohne `--pin` steht V5 als **uebersprungen** im Urteil.

Legen Sie ebenso das Zertifikat der Zeitstempelstelle mit `--tsa-cert` vor.
Ohne es prueft der Verifier die Token-Signatur gegen das **im Token
mitgefuehrte** Zertifikat und weiss nicht, wem dieses gehoert - es koennte
auch unseres sein. **V3 und V7 schreiben dann ausdruecklich, dass der
Aussteller nicht festgestellt ist**, statt einen von aussen bezeugten
Zeitpunkt zu behaupten. Ist das Signer-Zertifikat keines der vorgelegten,
fallen beide Schritte durch.

Bequemer geht es mit dem Beobachter-Werkzeug, das abholt, pruefen laesst
und einen Bruch berichtet:

```
python3 phm_beobachter.py --von https://<veroeffentlichungsort>/ --ablage ./beobachtung \
        --key-history archiv_manifest_key_history.json
```

Der Beobachter legt seinen Pin **write-once** ab (`0444`, beim Fortschreiben
ersetzt statt beschrieben), und ein fehlender Pin neben vorhandenen
`beobachtungen.jsonl` ist ihm ein Bruch statt eines Neuanfangs
([VERZEICHNIS.md](VERZEICHNIS.md), "Wenn der angeheftete Stand fehlt").
`phm_verifier.py --anheften` hat seit E20 (#354) **dieselbe Haertung aus
derselben Funktion**: die Anheft-Logik (Pin schreiben, Protokoll
fortschreiben, Gedaechtnisluecke erkennen) liegt im Verifier, und der
Beobachter laedt sie von dort, statt eine eigene zu fuehren. Der Pin entsteht
exklusiv neben der Zieldatei, wird gefsynct, auf `0444` gesetzt und per
`os.replace` an seine Stelle geschoben; daneben waechst `beobachtungen.jsonl`
um eine Zeile (beim Verifier ohne Zeitangabe, er hat keine Uhr), die den
Dateinamen des Pins traegt (`"pin"`). Mehrere Pins in einem Ordner teilen sich
die Datei, nicht das Gedaechtnis; Zeilen ohne `"pin"` (aeltere
Beobachter-Laeufe) gelten fuer `angehefteter_stand.json`. Fehlt ein Pin,
waehrend das Protokoll fruehere Anheftungen genau dieses Pins ausweist, endet
der Lauf mit Exit 1 und `"art": "gedaechtnisluecke"`, ohne zu pruefen oder
anzuheften. Ein
**vorhandener** Pin wird nur fortgeschrieben, wenn derselbe Lauf gegen genau
ihn geprueft hat (`--pin DATEI --anheften DATEI`); sonst Exit 2. Damit
koennen Sie den Verifier auch auf die Ablage des Beobachters ansetzen, und der
naechste Beobachterlauf baut darauf auf.

**Grenze, heute:** gegen einen Angreifer mit Schreibrecht am Ordner schuetzt
das nicht; wer Pin UND Protokoll entfernt, erzeugt den Zustand des echten
Erstlaufs. Bewahren Sie den Pin deshalb auch ausserhalb dieses Ordners auf
(Sicherung). Unter Windows bleibt es beim fsync der Datei; den Ordnereintrag
selbst bringt nur POSIX auf die Platte.

Der Beobachter rechnet ausserdem die **zugesagte Hoechstfrist zwischen zwei
Staenden** (14 Tage) gegen den juengsten Stand und meldet Verzug mit einem
eigenen Exit-Code `3`: ein eingefrorenes Verzeichnis ist in sich stimmig und
besteht jede Pruefung, waechst aber nicht mehr. Die Zusage und ihre
Begruendung stehen in [VERZEICHNIS.md](VERZEICHNIS.md).

### Staende untereinander weitergeben (Konsistenz-Paket)

Beobachter sind erst dann mehr als Zuschauer, wenn sie ihre Staende
**untereinander** halten koennen. Dafuer gibt es ein eigenstaendiges
Konsistenz-Paket (`paket_typ "phm-verzeichnis-konsistenz"`), das dieselbe
Verifier-Datei allein prueft:

```
python3 phm_verifier.py konsistenz.json --key-history archiv_manifest_key_history.json
```

Das Paket traegt **die beiden Koepfe im Original**, mit Signatur und
oeffentlichem Schluessel. Der Verifier prueft **K1** (beide Staende sind
echt signiert - dieselbe Pruefung wie V4) und **K2** (der spaetere Stand
enthaelt den frueheren unveraendert). Sie muessen dem, der Ihnen das Paket
gegeben hat, damit nichts glauben: die Signatur stammt von der Instanz, ein
manipulierter Kopf faellt in K1 auf. Legen Sie auch hier die
Schluesselhistorie vor - ohne sie bezeugt der Kopf seinen eigenen
Schluessel, und das steht so im Urteil.

Was das Paket nicht sagt: ob die beiden Koepfe in der Kopf-Kette
unmittelbar aufeinander folgen. Das sieht nur der volle Abzug.

Beide Dateien gehoeren nebeneinander. Rolle, Ablauf und die Grenzen des
Verzeichnisses stehen in [VERZEICHNIS.md](VERZEICHNIS.md) - insbesondere
die Bedingung, die hier zaehlt: **die Pruefung Ihrer Belegakte oder Ihres
Nachweises funktioniert ohne dieses Verzeichnis.** Es ist eine
zusaetzliche Aussage, nie eine Voraussetzung.

## Durchgespielt: Gate-A-Probe vom 30.07.2026

Dieses Werkzeug ist einmal vollstaendig gegen eine echte Akte gefahren
worden - in einer Umgebung ohne Netz und ohne Zugriff auf irgendeinen
Repo-Checkout, neben `shasum`, `bagit-python` und `openssl ts -verify`, und
zusaetzlich gegen vier manipulierte Fassungen derselben Akte. Die Probe hat
drei Fehler in unseren eigenen Werkzeugen gefunden (verweigerte Auslieferung,
uebersprungener Baum-Schritt, ungeprueft behauptete Anker-Zeit); alle drei
sind behoben und mit Regressionstests festgenagelt.

Protokoll, Fundstellen und die Grenzen des Nachweises:
`GATE_A_NACHWEIS.md` (nicht oeffentlich).
