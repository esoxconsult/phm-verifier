# Oeffentliches Verzeichnis der Archiv-Wurzeln (Z2)

> Auszug fuer das oeffentliche Pruef-Repository, erzeugt aus `docs/VERZEICHNIS.md` des
> Hauptrepositorys. Pfade sind auf dieses Repository umgeschrieben. Verweise
> mit dem Zusatz "(nicht oeffentlich)" und Vorgangsnummern wie #146 beziehen
> sich auf das Hauptrepository und sind hier nicht einsehbar.

Umsetzung von Issue #81. Vorbild: Certificate Transparency (RFC 6962), ohne
Blockchain, ohne Konsensverfahren, ohne Token - die Merkle-Struktur aus
#40 und #62 liefert alles Noetige.

## Die Luecke, um die es geht

Alles, was bisher gebaut ist, belegt **Unveraendertheit und Zeitpunkt**:
das Siegel (S2), der externe Anker (S3), die Wochen-Manifeste ueber der
Archiv-Wurzel (Z1 Teil 2). Nichts davon belegt, dass wir allen dieselbe
Geschichte erzaehlen. Wer den Index fuehrt, koennte einem Pruefer einen
Bestand zeigen und dem naechsten einen anderen; beide waeren in sich
stimmig, beide extern verankert, und keiner der beiden koennte es merken.

Das laesst sich **mit eigenen Mitteln nicht schliessen**, weil die
Schliessung eine fremde Beobachtung erfordert. Deshalb dieser Bau: die
Wurzeln liegen oeffentlich und nur anfuegbar, und beliebige Dritte koennen
sie beobachten. Ein Bestand, der zwei Geschichten erzaehlt, faellt dann auf
- nicht bei uns, sondern bei dem, der hinsieht.

### Die Luecke ist belegt, nicht vermutet

Das rote Team hat sie unabhaengig von diesem Bau nachgestellt (#101, Bericht
`ROTES_TEAM_01.md`, nicht oeffentlich). **Zwei Angriffe sind gelungen**, beide mit den
Faehigkeiten eines Betreibers, der den geheimen Schluessel hat:

- **A2, still ausgelassener Lauf.** Eine Kette, in der ein unbequemer Lauf nie
  gesiegelt wurde, ist in sich lueckenlos und besteht die Pruefung
  vollstaendig. Die Schritte 5 und 6 pruefen die innere Stimmigkeit der
  VORGELEGTEN Kette, nicht ihre Vollstaendigkeit.
- **A3, zwei Ketten parallel.** Zwei Bestaende derselben Instanz, mit
  demselben Schluessel gesiegelt, bestehen beide. Der Verifier sieht immer nur
  die eine Kette, die man ihm vorlegt.

Beide sind **ohne ein Verzeichnis nicht abwehrbar**: es gibt nichts, wogegen
ein Pruefer die vorgelegte Wurzel halten koennte. Dieser Bau ist damit keine
Ausbaustufe, sondern die Antwort auf zwei belegte Angriffe.

**Und er loest sie noch nicht.** Wirksam wird das Verzeichnis erst mit einem
Beobachter ausser Haus. Solange niemand ausser uns hinsieht, ist der Schutz
theoretisch: wir koennten zwei Verzeichnisse fuehren, so wie wir zwei Ketten
fuehren koennten, und niemand faende den Unterschied. A2 und A3 sind deshalb
**offen zu fuehren, nicht als geloest** - der Mechanismus steht, die Wirkung
haengt an einer Entscheidung und an einem Dritten (Punkt 1 unter "Offene
Entscheidungen").

## Die harte Bedingung

**Die Pruefung einer einzelnen Belegakte funktioniert OHNE dieses
Verzeichnis.** Wenn der Nachweis ohne uns nicht mehr gefuehrt werden
koennte, haetten wir eine neue Abhaengigkeit vom Aufzeichnenden geschaffen,
statt eine zu beseitigen.

Das ist keine Zusage, sondern ein Test: `test_belegakte_pruefung_braucht_
das_verzeichnis_nicht` gibt einen Zugehoerigkeitsnachweis aus, **loescht
das Verzeichnis vollstaendig** und prueft ihn danach in einem leeren Ordner
mit dem eigenstaendigen Verifier, ohne Netz. Das Verzeichnis ist eine
zusaetzliche Aussage, nie eine Voraussetzung.

Daraus folgt auch die Haftungsfrage: **wir sagen zur Verfuegbarkeit des
Verzeichnisses nichts zu.** Ist es einmal nicht erreichbar, ist keine
Pruefung blockiert; es fehlt dann nur die zusaetzliche Aussage.

## Was veroeffentlicht wird

```
verzeichnis.jsonl     append-only, eine Zeile je Eintrag
koepfe/kopf_*.json    signierte, verkettete Staende (write-once)
anker/anker_*.json    RFC-3161-Zeitstempel auf die Wurzel je Stand
INHALT.txt            was zum Abzug gehoert (fuer Beobachter)
LIESMICH.md           was das ist, und was es nicht ist
phm_beobachter.py     das Werkzeug der Beobachterrolle
```

Zwei Zeilentypen, mehr nicht:

- **`wurzel`**: ein signiertes Wochen-Manifest aus Z1 Teil 2, unveraendert
  uebernommen (Wurzel, Baumgroesse, Index-Prueffsumme, Woche,
  Vorgaenger-Hash, Ed25519-Signatur, oeffentlicher Schluessel).
- **`anker`**: ein RFC-3161-Token auf die Wurzel eines Manifests, das
  bereits im Verzeichnis steht - mit vollem Token, damit jeder den
  Zeitpunkt selbst nachpruefen kann, ohne uns zu fragen.

Jede Zeile traegt zusaetzlich `nr`, `typ`, `veroeffentlicht_at` und `prev`
(SHA-256 ueber die rohen Bytes der Vorgaengerzeile, Genesis = SHA-256 der
leeren Eingabe).

### Zwei Ebenen der Verkettung, beide absichtlich

1. **`prev` je Zeile.** Entfernen, Einfuegen und Umsortieren faellt beim
   blossen Durchlesen auf - ohne Baum, ohne Schluessel, ohne unser Werkzeug.
2. **Merkle-Baum ueber alle Zeilen** (RFC 6962, dieselben Funktionen wie
   Siegel- und Archiv-Baum). Erst er erlaubt den **Konsistenznachweis**:
   wer nur `(Groesse, Wurzel)` eines frueheren Standes aufbewahrt hat,
   prueft mit wenigen Knoten-Hashes, dass der heutige Stand den frueheren
   unveraendert enthaelt. Das ist die eigentliche Funktion; ohne sie waere
   das hier nur eine Liste.

### Der Kopf: ein Stand des Verzeichnisses

`koepfe/kopf_NNNNNNNN.json`, write-once (O_EXCL, 0444), verkettet ueber
`prev_kopf_hash`, signiert mit Ed25519. Signierte Felder in fester
Reihenfolge, flach als `name:wert` je Zeile - ein Dritter reproduziert die
Bytes trivial:

```
kopf_version, sig_algo, hash_algo, key_id, created_at, kopf_nr,
tree_size, root_hash, datei_pruefsumme, prev_kopf_hash
```

`kopf_hash` bindet Inhalt UND Signatur (Muster S2): ein neu signierter Kopf
aendert seinen Hash und bricht die Kette.

**Schluessel:** derselbe Archiv-Manifest-Schluessel wie in Z1 Teil 2
(key_id-Raum `am-`). Bewusst kein dritter Schluesselraum: wer den
`am-`-Schluessel hat, kann ohnehin Manifeste bilden, ein eigenes Paar
brauchte eigene Verwahrung und braechte keine zusaetzliche Aussage. Wenn
das anders entschieden wird, ist es eine Formatversion wert (offene
Entscheidungen unten).

**Anker je Eintrag, und zwar nachgesehen:** Vorgabe ist ein
externer Anker je Eintrag. Erfuellt wird sie zeitversetzt - eine Wurzel
wird veroeffentlicht, ihr Anker folgt im selben oder im naechsten Lauf.
Damit daraus kein stiller Verzicht wird, prueft **V3 die Deckung** und
nicht nur die Echtheit der vorhandenen Token: jede Wurzel ohne jeden
Anker ist ein Befund, ausser der juengsten (die darf zwischen Wurzel- und
Ankerlauf offen sein). Dasselbe prueft `--pruefen` auf unserer Seite,
damit wir es vor dem Beobachter merken.

**Anker auf den Kopf:** dieselbe Anker-Mechanik wie ueberall (bis zu
zwei Zeitstempelstellen, `direkt` genau einmal je Kopf und Stelle,
`erneuerung` wiederholbar; gepinnt ist in diesem Repository nur
freetsa.org). Fehlt eine TSA, bleibt der Anker sichtbar
offen; ein Kopf ohne Anker wird gemeldet, nie stillschweigend verzichtet.

### Nachrechnen ohne unseren Code

Zwei Werte im Kopf lassen sich mit einem Standardwerkzeug nachrechnen,
ohne Python und ohne dieses Repo. Aus dem Abzugsordner:

```bash
shasum -a 256 verzeichnis.jsonl
printf '%s' "$(sed -n '3p' verzeichnis.jsonl)" | shasum -a 256
```

Der erste Befehl liefert `datei_pruefsumme` des juengsten Kopfes (ohne das
Praefix `sha256:`) - die ganze Datei, **einschliesslich** des
abschliessenden Zeilenumbruchs. Der zweite liefert die Blatt-Eingabe der
dritten Zeile, also den Wert, aus dem der Merkle-Baum ueber die Zeilen
gebildet wird: SHA-256 ueber die rohen Bytes der Zeile, **ohne**
Zeilenumbruch (`$(...)` schneidet ihn ab). Fuer eine andere Zeile die `3`
ersetzen. Unter GNU-Systemen ohne `shasum` tut es `sha256sum` mit gleichem
Ergebnis.

**Gibt es die Zeile nicht** - ein frueher Abzug hat weniger als drei -, dann
hasht der Befehl die leere Eingabe und liefert
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Das ist
kein Wert dieses Verzeichnisses, sondern das Zeichen dafuer, dass die Zeile
fehlt; `wc -l verzeichnis.jsonl` sagt vorher, wie viele es gibt. Der Wert
steht hier, weil er sonst wie ein Ergebnis aussieht.

**Was nicht funktioniert**, weil es zwischen den beiden Faellen sitzt:

```
printf '%s' "$(cat verzeichnis.jsonl)" | shasum -a 256
```

Das hasht die ganze Datei **ohne** den abschliessenden Zeilenumbruch und
stimmt deshalb mit `datei_pruefsumme` nie ueberein - und mit keiner
Blatt-Eingabe auch nicht. Der Befehl stand in dieser Form im PR-Text zu
#102, ist dort richtiggestellt und steht hier als Warnung (#163).

Beide Zeilen des oberen Blocks werden von
`test_fremdnachrechnung_stimmt_mit_dem_kopf_ueberein` **aus dieser Datei
gelesen und ausgefuehrt**, gegen einen echten Abzug; die falsche Form ist
dort als Gegenprobe festgehalten. Ein Handlauf, den niemand nachvollziehen
kann, ist schlechter als keiner.

## Was das Verzeichnis NICHT kann

Der Unterschied wird hier benannt und nicht verwischt:

- **Es beweist keine Vollstaendigkeit im Sinne von "alles
  Archivierungswuerdige ist archiviert".** Ein Dokument, das nie archiviert
  und nie veroeffentlicht wurde, fehlt hier genauso unbemerkt wie vorher.
  Was es beweist: dass der **veroeffentlichte Bestand** nachtraeglich nicht
  veraendert wurde und dass alle denselben sehen.
- **Es beweist nichts ohne Beobachter.** Ein einzelner Abzug kann nur in
  sich stimmig sein. Die Aussage entsteht erst im Vergleich mit dem, was
  frueher zu sehen war - also erst ab dem zweiten Lauf eines Beobachters,
  der den ersten Stand aufbewahrt hat.
- **Es sagt nichts ueber die fachliche Richtigkeit** einer Zahl, einer
  Regel oder eines Urteils.
- **Es schuetzt nicht davor, dass wir von Anfang an nichts eintragen.**
  Wer nie etwas veroeffentlicht, faelscht auch nichts.

### Was es dennoch verraet

Ehrlich, statt als Fussnote: aus dem Verzeichnis ist die **Anzahl der
Archiv-Eintraege** ablesbar (`tree_size` der Manifeste), der **Rhythmus**
unserer Laeufe (`created_at`, `woche`), unsere **Schluessel-Kennungen** und
welche **Zeitstempelstellen** wir nutzen. Kein Dokument, keine Fundstelle,
keine Prueffsumme eines Dokuments, kein Kunde, kein Portfolio - das ist
maschinell geprueft (`test_verzeichnis_traegt_keinen_inhalt`, Schritt V6 des
Verifiers meldet jedes unbekannte Feld als Befund, weil es ein Kanal waere).

## Die Beobachterrolle

**Ein Verzeichnis ohne Beobachter ist ein Logbuch.** Solange nur wir
hinsehen, ist der Mehrwert theoretisch. Ein einziger externer Beobachter -
und sei es der spaetere Wirtschaftspruefer eines Kunden - macht den
Unterschied.

Was ein Beobachter tut, in dieser Reihenfolge:

0. **Das eigene Gedaechtnis pruefen.** Fehlt `angehefteter_stand.json`,
   waehrend `beobachtungen.jsonl` frueherer Laeufe vorliegt, ist der Lauf zu
   Ende (Exit 1, `BRUCH_<zeit>.json` mit `"art": "gedaechtnisluecke"`). Siehe
   [Wenn der angeheftete Stand fehlt](#wenn-der-angeheftete-stand-fehlt).
1. **Abholen.** `phm_beobachter.py --von <URL> --ablage ./beobachtung`.
   Geholt wird, was `INHALT.txt` auflistet - keine Verzeichnislisten, keine
   Rateschleifen, mit Groessengrenzen (der Beobachter laedt von einer
   Stelle, der er gerade nicht vertraut).
2. **Pruefen lassen.** Der Beobachter bringt bewusst **keine eigene
   Kryptographie** mit; er setzt `phm_verifier.py` an, dieselbe eine Datei,
   die auch Belegakten prueft. Eine zweite, schlechtere Implementierung
   waere kein Gewinn.
3. **Anheften.** Bei bestandener Pruefung wird der juengste Stand
   aufbewahrt (`angehefteter_stand.json`) und der Abzug als letzter guter
   abgelegt. Ab dem naechsten Lauf ist er der Bezugspunkt. Der Pin ist
   **write-once wie die Koepfe**: er traegt `0444` und wird beim
   Fortschreiben ersetzt (exklusiv daneben geschrieben, gefsynct,
   `os.replace`), nicht beschrieben. Diese Anheft-Logik steht genau einmal,
   in `phm_verifier.py` (E20, #354); der Beobachter laedt sie von dort, und
   `phm_verifier.py --anheften` benutzt dieselbe. Ein Verifier, der sie nicht
   kennt (aelter als E20), ist fuer den Beobachter ein unvollstaendiger Lauf
   (Exit 2), kein Rueckfall auf eine eigene Fassung.
4. **Melden.** Bei einem Befund entsteht ein `BRUCH_<zeit>.json` mit dem
   vollen Ergebnis, dem angehefteten Stand und dem Pfad zum geholten Abzug.
   Der angeheftete Stand wird **nicht** fortgeschrieben: ein gescheiterter
   Abzug darf nie zum neuen Bezugspunkt werden.
5. **Die Frist rechnen.** Nach bestandener Pruefung haelt der Beobachter das
   Alter des juengsten Standes gegen die Hoechstfrist unten und meldet
   **Verzug**, wenn sie ueberschritten ist.

Exit-Codes: `0` geprueft und vertraeglich, `1` nicht bestanden (im Zweifel
Bruch, Bericht ansehen), `2` Abholung oder Verifier unbrauchbar - **das ist
kein Freispruch, sondern ein unvollstaendiger Lauf** -, `3` **Verzug** (siehe
unten): der Abzug ist in sich stimmig, aber zu alt.

### Die zugesagte Hoechstfrist zwischen zwei Staenden: 14 Tage

**Wir sagen zu, dass zwischen zwei veroeffentlichten Staenden hoechstens
14 Tage (336 Stunden) liegen.** Der Betriebsrhythmus ist woechentlich
(Abschnitt Betrieb); ein ausgefallener Lauf ist damit noch kein Befund, zwei
sind einer.

Diese Zahl ist eine **Zusage, keine Messgroesse.** Sie ist entschieden, nicht
aus dem Betrieb abgeleitet, und sie bindet uns: wer sie aendert, aendert eine
oeffentliche Zusage. Im Werkzeug steht sie an genau einer Stelle
(`MAX_STAND_ABSTAND_STUNDEN` in `phm_beobachter.py`).

**Warum es sie ueberhaupt braucht.** Eine Luecke INNERHALB der Folge faengt
V2 - die Nummern muessen lueckenlos sein. Ein stehengebliebener Schwanz faengt
niemand: ein eingefrorenes oder am Ende abgeschnittenes Verzeichnis ist in
sich vollkommen stimmig und besteht jede einzelne Pruefung, auf Dauer. Damit
staende **A2** (der still ausgelassene Lauf, siehe oben) am Verzeichnis
selbst - also an der Antwort auf A2. Wer unbequeme Staende nicht faelscht,
sondern das Veroeffentlichen einstellt, fiele sonst niemandem auf.

Das Vorbild ist die **maximale Merge-Verzoegerung (MMD)** der Certificate
Transparency: ein Log, das laenger als zugesagt nichts anhaengt, ist im
Verzug, und der Verzug ist ein Befund.

**Warum der Beobachter das rechnet und nicht der Verifier.** Der Verifier hat
bewusst keine Uhr - dieselbe Eingabe soll immer dasselbe Urteil ergeben,
offline und reproduzierbar. Frische ist aber eine Aussage ueber JETZT. Sie
gehoert deshalb dorthin, wo ohnehin eine Uhr laeuft und wo das Hinsehen ueber
die Zeit die ganze Rolle ist.

**Gerechnet wird an zwei Stellen, nicht an einer.** Am Ende (juengster Stand
gegen jetzt) faengt das eingefrorene Verzeichnis. Zwischen zwei
veroeffentlichten Staenden faengt das Nachschieben: wer drei Wochen schweigt
und dann zwei Koepfe auf einmal anhaengt, haette am Ende einen frischen Stand
und die Zusage trotzdem gebrochen. Die Abstaende werden **ab Ihrem
angehefteten Stand** gerechnet - die Zusage gilt ab ihrer Veroeffentlichung
und nicht rueckwirkend, und ein Beobachter sagt ohnehin nur ueber die Zeit
aus, in der er hingesehen hat.

Verzug ist **kein Bruch**: alles, was veroeffentlicht wurde, bleibt
vertraeglich. Er bekommt deshalb einen eigenen Bericht (`VERZUG_<zeit>.json`)
und einen eigenen Exit-Code. Ein Stand, dessen `created_at` fehlt oder
unlesbar ist, gilt ausdruecklich **nicht** als frisch - dann laesst sich die
Frist nicht rechnen, und ungerechnet ist sie kein Freispruch.

### Wenn der angeheftete Stand fehlt

Der Pin ist das ganze Gedaechtnis dieser Rolle. Ohne ihn bleibt V5 aus, und
ein Lauf heftet den vorgefundenen Stand als **ersten** an - jede Vorgeschichte
waere damit eingeebnet. Das ist die Angriffsform, gegen die das Verzeichnis
gebaut ist, angewandt auf den Beobachter selbst: wer den Pin loeschen kann,
loescht das Gedaechtnis, und der naechste Lauf bestaetigt jeden Stand als
Anfangsstand. Es braucht dafuer keinen Angreifer, ein aufgeraeumtes
Verzeichnis genuegt.

Unterschieden wird deshalb nach der Kombination, nicht nach dem Fehlen:

| `angehefteter_stand.json` | `beobachtungen.jsonl` | |
|---|---|---|
| fehlt | fehlt | **echter Erstlauf**, Exit 0. V5 uebersprungen, der Hinweis steht im Urteil; die Aussage entsteht ab dem naechsten Lauf |
| fehlt | vorhanden | **Gedaechtnisluecke**, Exit 1. "Schon beobachtet, aber nicht mehr wissen was" ist kein Anfangszustand |
| vorhanden | - | Regelfall, V5 laeuft |

Der Bruchbericht traegt die Begruendung im `ergebnis`, nicht nur in stdout -
ein Cron liest die Datei, nicht den Bildschirm.

Dieselbe Tabelle gilt fuer `phm_verifier.py --anheften DATEI` (E20, #354):
das Protokoll ist dort `beobachtungen.jsonl` im Ordner von `DATEI`, jede
Zeile traegt den Pin-Namen (`"pin"`), und gezaehlt werden nur die Zeilen von
`DATEI` (Zeilen ohne `"pin"` stammen aus aelteren Beobachter-Laeufen und
gelten fuer `angehefteter_stand.json`). Die Gedaechtnisluecke endet mit Exit 1 (mit `--json` als Ergebnis-Objekt mit
`"art": "gedaechtnisluecke"`), und ein vorhandener Pin wird nur zusammen mit
`--pin DATEI` fortgeschrieben, sonst Exit 2. Beide Werkzeuge fahren dieselbe
Funktion, und ein Test faehrt denselben Fall durch beide.

**Abhilfe**, in dieser Reihenfolge: den Pin aus der Sicherung zurueckholen.
Ist er endgueltig weg, die Beobachtung **bewusst** neu beginnen - dazu das
Protokoll unter neuem Namen aufbewahren (`beobachtungen_bis_<datum>.jsonl`),
damit der Neubeginn eine Spur hinterlaesst, statt eine zu loeschen. Beides ist
Handarbeit; einen Schalter, der die Luecke wegnimmt, gibt es absichtlich
nicht. Ein Cron, der ihn setzen koennte, waere wieder der stille Reset.

### Was der Verifier prueft (Schritte V1 bis V7)

`python3 phm_verifier.py <ABZUG> [--pin PIN.json] [--anheften PIN.json]
--key-history HISTORIE.json [--tsa-cert ZERTIFIKAT.pem]`

`--key-history` ist der vorgesehene Weg. `--public-key HEX` gibt es
weiterhin fuer den Fall, dass jemand nur einen einzelnen Schluessel zur Hand
hat; er scheitert an der ersten Rotation. **Werden beide angegeben, hat die
Historie Vorrang und `--public-key` wird NICHT zusaetzlich angewandt**
(entschieden zu #161). Konjunktiv angewandt scheiterte die Kombination
ueber einem rotierten Abzug zwangslaeufig: ein einzelner Schluessel kann
nicht zu allen Objekten passen, sonst gaebe es die Rotation nicht. Das
Werkzeug sagt es beim Aufruf auf stderr, und der Bericht weist in V2 und V4
aus, dass der Einzelschluessel unangewandt blieb.

| | |
|---|---|
| V1 | Zeilenkette: kanonische Form, Nummernfolge, `prev`-Verkettung |
| V2 | die veroeffentlichten Wochen-Manifeste: Ed25519, Kette, Monotonie |
| V3 | die veroeffentlichten Anker: volle CMS-Pruefung, `messageImprint` = Wurzel, **die Deckung** (eine Wurzel ohne jeden Anker ist ein Befund, ausser der juengsten) **und die Zeit** (siehe unten) |
| V4 | Koepfe: Kette, Signatur, **jede** Wurzel aus den Zeilen neu gerechnet |
| V5 | Vertraeglichkeit mit dem angehefteten Stand (Konsistenz, RFC 6962 2.1.4) |
| V6 | Datensparsamkeit: unbekannte Felder sind ein Befund |
| V2/V4 | Schluessel je Manifest und je Kopf ueber die `key_id` gegen die veroeffentlichte Historie (`--key-history`) aufgeloest, samt Gueltigkeitsfenster. **Ein unbekannter Schluessel faellt in beiden Schritten auf, und den UEBERGANG zwischen zwei Schluesseln pruefen seit #159 ebenfalls beide** (steht der alte laut Historie noch, als der neue schon signiert, ist das ein Befund; `valid_to: null` heisst dabei "laeuft noch", nicht "kein Fenster"). Ein einzelner `--public-key` scheitert an der ersten Rotation. Was am Fenster wirklich verglichen wurde, steht im Bericht (siehe unten) |
| V7 | Externe Anker auf die KOEPFE (RFC 3161): je Kopf messageImprint gegen die Kopf-Wurzel, Token-Signatur, und Deckung ueber alle Koepfe. Der juengste Kopf darf zwischen Kopf- und Anker-Lauf noch offen sein (wie V3), ein aelterer nicht. Ohne diesen Schritt waere nur bezeugt, was IM Verzeichnis steht, nicht der veroeffentlichte Stand selbst. Dazu der Zeitvergleich (siehe unten) |
| V3/V7 | **Wer das Token ausgestellt hat, sagt erst `--tsa-cert`.** Ohne vorgelegtes Vertrauenszertifikat ist die Signatur gegen das IM TOKEN mitgefuehrte Zertifikat geprueft - dass der Zeitpunkt von AUSSEN bezeugt ist, steht dann nicht fest, und beide Schritte sagen das auch so. Ein Signer-Zertifikat, das keines der vorgelegten ist, ist in beiden Schritten ein Fehlschlag |

Ohne `--pin` wird V5 als **uebersprungen** ausgewiesen und steht so im
Gesamturteil; uebersprungen wird nie zu bestanden (die Lehre aus dem
Gate-A-Befund Nr. 2, PR #52).

#### Was der Anker ueber die Zeit sagt, und was nicht (V3 und V7)

Ein RFC-3161-Token bezeugt, dass ein **Hash** zu einem Zeitpunkt existierte.
Es bezeugt nicht, dass der Datensatz daneben zu dem Zeitpunkt entstand, den er
selbst in `created_at` behauptet. Bis #145 wurden die beiden Zeiten nie
gegeneinander gehalten: ein heute gebauter Strang mit `created_at` von 2020,
heute frisch verankert, bestand V3 und V7 anstandslos - und der Bericht sagte
dazu "ein Zeitpunkt, den nicht wir bezeugen". Wer das las, dachte an 2020;
bezeugt war heute.

Seither vergleichen V3 (je Manifest) und V7 (je Kopf) beide Zeiten, in beide
Richtungen:

| Lage | Ergebnis | warum |
|---|---|---|
| `created_at` bis 72 h vor `genTime` | still | der Normalfall: erst der Stand, dann sein Anker |
| `created_at` **deutlich vor** `genTime` (> 72 h) | **BEFUND**, kein Fehlschlag | der legitime Nachhol-Fall (S3, Anker spaeter) sieht genauso aus wie eine Rueckdatierung. Der Bericht nennt beide Zeiten und sagt, dass das Token den frueheren Zeitpunkt nicht bezeugt |
| `created_at` **nach** `genTime` (> 60 s) | **FEHLSCHLAG** | die Wurzel war bezeugt, bevor der Stand entstanden sein will, der sie bildet. Einen legitimen Weg dorthin gibt es nicht |

Die Schwellen sind dieselben Konstanten wie im Siegel-Pfad
(`SCHWELLE_ANKER_ABSTAND_STUNDEN`, `TOLERANZ_UHRENVORLAUF_SEKUNDEN`); die
Haertung ist von dort uebertragen, nicht neu erfunden.

**Die Grenze der zweiten Zeile, ausdruecklich:** im Siegel-Pfad ist sie
kryptografisch zwingend, weil der bezeugte Hash das `sealed_at` selbst
enthaelt. Hier enthaelt der bezeugte Hash die Zeitangabe nicht - die Wurzel
steht ueber den Zeilen, nicht ueber dem Kopf. Zwingend ist die Richtung hier
durch den Ablauf: die Wurzel entsteht beim Bilden des Standes, ein Token
darauf kann es vorher nicht geben.

#### Woher die Schluesselhistorie kommt, entscheidet, was sie wert ist

`--key-history` liest eine gewoehnliche JSON-Datei. Der Verifier prueft ihr
Schema und doppelte `key_id`, sonst nichts: **die Historie ist nicht signiert
und nicht verankert.** Wer den Abzug ausliefert, kann eine dazu passende
Historie gleich mitliefern - und V2 und V4 werden gruen, weil sie gegen genau
diese Datei pruefen.

**Beziehen Sie die Historie deshalb aus einer Quelle ausserhalb des Abzugs**
(`keys/*_key_history.json` im veroeffentlichten Repo), und bewahren Sie
Ihren eigenen Stand auf. Das ist der Sinn von `--anheften`: der Pin ist das
einzige Stueck Zustand, das bei Ihnen liegt und nicht vom Herausgeber kommt.

Seit #146 haelt **V5** den Schluessel aus Ihrem Pin gegen den heutigen Abzug:

| Lage | Ergebnis |
|---|---|
| gleiche `key_id`, gleicher `public_key`, **durchgehend** | still, unveraendert |
| heute wieder Ihr Schluessel, aber dazwischen hat ein anderer unterschrieben | **BRUCH** - "heute derselbe" ist keine Aussage ueber die Strecke |
| gleiche `key_id`, **anderer** `public_key` | **BRUCH** - ein Tausch unter gleichem Namen |
| Ihr angehefteter Kopf traegt hier einen anderen Schluessel | **BRUCH** |
| die Historie fuehrt Ihre `key_id` mit einem anderen `public_key` | **BRUCH** - sie widerspricht Ihrer eigenen Beobachtung |
| Wechsel der `key_id`, **erklaert** | bestanden, im Bericht benannt |
| Wechsel der `key_id`, **unerklaert** | **BRUCH** |

Erklaert heisst: beide Schluessel stehen in der Historie, der Eintrag zu Ihrem
alten Schluessel traegt noch den `public_key`, den Sie angeheftet haben, der
alte Schluessel ist mit einem `valid_to` **abgelegt**, das Fenster des neuen
**schliesst daran an**, und die Kopf-Kette zeigt ab Ihrem Stand genau einen
Uebergang. Ein alter Schluessel, der in der Historie offen bleibt (`valid_to`
null), waehrend daneben ein zweiter unterschreibt, ist keine Rotation, sondern
sind zwei gleichzeitig gueltige Schluessel - und damit ein Bruch.

**Die Grenze, ausdruecklich:** wer den Abzug UND die Historie beherrscht und
beim Wechsel sauber arbeitet (alten Eintrag unveraendert lassen, `valid_to`
nachtragen, neuen Schluessel anschliessen), ist von einer echten Rotation nicht
zu unterscheiden. Dagegen hilft nur eine Historie, die selbst signiert oder
verankert ist; das ist offen. Was der Pin leistet, ist enger und trotzdem der
Kern: **jede Aenderung an dem, was Sie selbst schon gesehen haben, faellt auf.**

#### Das Gueltigkeitsfenster: was verglichen wird, und was nicht

`valid_from` und `valid_to` sind **Angaben in der Historie**, keine Beweise -
und sie sind oft gar nicht gesetzt. Der Bericht sagt deshalb nicht mehr
pauschal "Gueltigkeitsfenster geprueft", sondern was vorlag: wie viele
Eintraege beidseitig begrenzt waren, wie viele einseitig, und wie viele **ohne
jede Angabe** - dort wurde nichts verglichen. Nichts vergleichen zu koennen ist
kein Fehler; es als Pruefung auszugeben schon.

Zwei Regeln dazu:

- **Format wie bei `created_at`.** `valid_from`/`valid_to` muessen
  `YYYY-MM-DDThh:mm:ssZ` oder `null` sein. Der Vergleich laeuft ueber
  Zeichenketten; eine Angabe in anderer Form (`2026-08-04`, `04.08.2026`,
  `...+00:00`) liefert ein Ergebnis, nur nicht das gemeinte. Eine Historie in
  abweichendem Format wird deshalb abgewiesen statt still verglichen.
- **`valid_to: null` heisst "laeuft noch", nicht "kein Fenster".** Signiert ein
  anderer Schluessel, waehrend der vorige laut Historie noch gilt, ist das
  keine Rotation, sondern zwei gleichzeitig gueltige Schluessel - und damit ein
  Befund. **Wer einen Schluessel ablegt, traegt sein `valid_to` nach.** Seit
  #174 traegt in `keys/` je Schluesselraum genau ein Eintrag
  `valid_to: null`; die beiden Demo-Schluessel sind auf den Beginn der
  produktiven gesetzt, und `backend/tests/test_schluesselhistorien.py` (nicht oeffentlich) haelt die Regel
  fest.

### Das Konsistenz-Paket: das Austauschformat zwischen Beobachtern

Ein Konsistenznachweis laesst sich als eigenstaendiges Paket weitergeben
(`tools/verzeichnis.py --konsistenz ALT:NEU --paket DATEI` (nicht oeffentlich), `paket_typ
"phm-verzeichnis-konsistenz"`); der Verifier erkennt und prueft es allein.

**Paketversion 2 (#155): es traegt die beiden Koepfe im Original**, mit
`signature` und `public_key`, statt eines eigens gebauten Ausweises aus
sechs Feldern. Der Unterschied ist der ganze Zweck. Ein Verzeichnis, das
nur wir veroeffentlichen, schuetzt gegen unsere Fehler, nicht gegen uns;
wirksam wird es erst, wenn Beobachter ihre Staende **untereinander** halten
koennen - und das setzt voraus, dass ein Stand seinen Urheber traegt. Beim
unsignierten Ausweis konnte B nicht unterscheiden, ob der Stand von A
stammt oder von uns. Jetzt ist die Signatur die unsere, und wer das Paket
weitergibt, reicht weiter, was er bekommen hat, statt etwas Neues zu
behaupten.

| | |
|---|---|
| K1 | Echtheit beider Staende: Ed25519 ueber den eingebetteten Kopf, `kopf_hash` bindet Inhalt und Signatur - derselbe Weg wie V4, mit `--key-history` derselbe Bezug auf die veroeffentlichte Historie |
| K2 | Vertraeglichkeit: der spaetere Stand enthaelt den frueheren unveraendert (RFC 6962 2.1.4), gerechnet ueber Groesse und Wurzel **aus den signierten Koepfen** |

Faellt K1, ist das Paket unbrauchbar, gleich was K2 meldet: ein Pfad, der
ueber erfundene Wurzeln aufgeht, ist ein korrekter Beweis fuer nichts.

Was das Paket **nicht** sagt: ob die beiden Koepfe in der veroeffentlichten
Kopf-Kette unmittelbar aufeinander folgen und ob es zwischen ihnen weitere
Staende gab. Das sieht nur, wer den vollen Abzug prueft (V4). Pakete der
Version 1 werden sichtbar abgewiesen statt still akzeptiert - sie trugen
als Nachweis nichts.

## Betrieb

*Ausgelassen: der Abschnitt beschreibt den Ablauf auf Herausgeberseite und
steht nur im Hauptrepository (nicht oeffentlich).*

## Offene Entscheidungen

1. **Wo wird veroeffentlicht, und was passiert, wenn dieser Ort ausfaellt?**
   Ein Verzeichnis, das nur bei uns liegt, ist schwaecher als eines, das
   gespiegelt wird. Der Code macht keine Vorgabe: `--spiegeln` schreibt in
   einen Ordner, und wo der liegt (eigene Domain, Objektspeicher, ein
   oeffentliches Git-Repo, mehrere davon), ist eine Entscheidung, keine
   Technik. Empfehlung: mindestens zwei Orte, davon einer nicht bei uns.
2. **Wer beobachtet ausser uns?** Ohne mindestens einen fremden Beobachter
   bleibt der Mehrwert theoretisch. Der naheliegendste erste ist der
   Wirtschaftspruefer eines Pilotkunden; er braucht nichts als die zwei
   Dateien und einen Cron-Eintrag.
3. **Eigenes Schluesselpaar fuer den Verzeichnis-Kopf?** Heute `am-`
   (Begruendung oben). Wenn die Verwahrung getrennt werden soll, ist das
   eine neue `kopf_version`, kein Umbau.
4. **Haftung.** Vorschlag: keine Verfuegbarkeitszusage, weil die Pruefung
   ohne das Verzeichnis funktioniert. Das steht so oben und gehoert, wenn
   es bleibt, in die Verfahrensregeln.

## Ehrliche Grenzen

- **Wirkung nur mit Veroeffentlichung.** Ein Verzeichnis, das niemand
  sieht, beweist niemandem etwas; wo es veroeffentlicht wird, ist Punkt 1
  oben.
- **Kein fremder Beobachter.** Der einzige gefahrene Beobachterlauf ist
  unser eigener Test. Damit bleiben **A2 und A3 aus #101 offen** und sind
  auch so zu fuehren; der Mechanismus schafft die Voraussetzung ihrer Abwehr, er
  vollzieht sie nicht.
- **Ein Zeitstempeldienst gepinnt.** Vorgesehen sind zwei Zeitstempelstellen;
  gepinnt und damit in diesem Repository pruefbar ist nur freetsa.org. Das
  Token einer anderen Stelle faellt mit `--tsa-cert` in V3/V7, bis deren
  Zertifikat hier ergaenzt ist.
- **Der Beobachter prueft die TLS-Gegenstelle nicht besonders** - er nutzt
  die Standardpruefung von Python. Wer streng beobachtet, holt ueber einen
  eigenen Weg und legt `--tsa-cert` und `--key-history` selbst vor (nicht
  `--public-key`: der scheitert an der ersten Rotation, und neben einer
  Historie bleibt er ohnehin unangewandt).
- **Die Grenze der TSA-Kette** ist dieselbe wie ueberall (S4): Kette zur
  Wurzel und Sperrstatus prueft der Beobachter mit `openssl`, nicht dieses
  Werkzeug.

## Abgrenzung

Keine Blockchain, kein Konsensverfahren, kein Token. Kein
Gossip-Protokoll zwischen Beobachtern (das waere der naechste Schritt, wenn
es je mehrere gibt). Keine Aussage ueber Vollstaendigkeit des Archivierens.
