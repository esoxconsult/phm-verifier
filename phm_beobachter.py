#!/usr/bin/env python3
"""
Beobachter des PHM-Wurzelverzeichnisses (Z2, Issue #81).

Ein Verzeichnis ohne Beobachter ist ein Logbuch. Dieses Skript ist der
Beobachter: es holt den veroeffentlichten Abzug regelmaessig ab, laesst ihn
gegen den zuletzt gesehenen Stand pruefen und meldet einen Bruch.

WER DAS LAUFEN LASSEN SOLLTE: jemand, der nicht wir ist. Ein Kunde, sein
Wirtschaftspruefer, ein Aufsichts- oder Verbandsvertreter, ein befreundetes
Haus. Solange nur wir hinsehen, ist der Mehrwert theoretisch - das
Verzeichnis wirkt durch fremde Beobachtung, nicht durch Existenz.

WAS ES SELBST NICHT TUT: pruefen. Die Pruefung macht phm_verifier.py, die
eine Datei, die auch Belegakten prueft; dieses Skript holt ab, verwahrt den
angehefteten Stand und schreibt einen Bericht. Es bringt bewusst keine
eigene Kryptographie mit - eine zweite, schlechtere Implementierung waere
kein Gewinn.

Ablauf eines Laufs:
  0. Das eigene Gedaechtnis pruefen: fehlt der angeheftete Stand, WAEHREND
     beobachtungen.jsonl frueherer Laeufe vorliegt, ist der Lauf zu Ende
     (Exit 1). "Schon beobachtet, aber nicht mehr wissen was" ist kein
     Anfangszustand - der echte Erstlauf hat beides nicht.
  1. Abzug holen (HTTP/HTTPS oder ein Pfad, z. B. ein gespiegelter Ordner).
     Geholt wird, was INHALT.txt auflistet - keine Verzeichnislisten, keine
     Rateschleifen.
  2. phm_verifier.py auf den Abzug ansetzen, mit dem angehefteten Stand
     (--pin), sofern schon einer vorliegt.
  3. Bestanden: der neue Stand wird angeheftet, der Abzug als letzter guter
     aufbewahrt. Nicht bestanden: BRUCH-Bericht schreiben, den Abzug UND
     den bisherigen Pin unveraendert aufbewahren (beide sind der Beleg),
     und den Pin NICHT fortschreiben.

Der angeheftete Stand ist write-once wie die Koepfe: er traegt 0444 und wird
beim Fortschreiben ersetzt, nicht beschrieben. Diese Logik (Pin schreiben,
Protokoll fortschreiben, Gedaechtnisluecke erkennen) fuehrt dieses Skript
NICHT selbst: es laedt sie aus phm_verifier.py, damit `phm_verifier.py
--anheften` und dieser Beobachter dieselbe eine Umsetzung benutzen (E20,
#354). Zwei Umsetzungen derselben Sicherheitslogik laufen auseinander.

Aufruf:
    python3 phm_beobachter.py --von https://.../verzeichnis/ --ablage ./beobachtung
    python3 phm_beobachter.py --von /pfad/zum/abzug --ablage ./beobachtung

Exit 0 = geprueft und vertraeglich; 1 = Pruefung nicht bestanden (im
Zweifel: BRUCH, Bericht ansehen); 2 = Aufruf, Abholung oder Verifier
unbrauchbar - das ist KEIN Freispruch, sondern ein unvollstaendiger Lauf;
3 = VERZUG: der Abzug ist in sich stimmig, aber aelter als die zugesagte
Hoechstfrist (#156). Eigener Code, weil es eine andere Aussage ist als ein
Bruch - die Kette ist heil, sie waechst nur nicht mehr.

Nur Python-Standardbibliothek, Python 3.8 oder neuer.
"""
from __future__ import annotations

import argparse
import calendar
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, List, Optional, Tuple

VERZEICHNIS_DATEI = "verzeichnis.jsonl"
INHALT_DATEI = "INHALT.txt"
VERIFIER = "phm_verifier.py"

# Die Ablage des Beobachters: der angeheftete Stand und, daneben, das
# Protokoll der Laeufe (Name und Lage legt phm_verifier.py fest,
# BEOBACHTUNGEN_DATEI). Beide zusammen sind sein Gedaechtnis, und die
# Kombination "Protokoll ja, Stand nein" ist genau die, die auffallen muss
# (#154).
PIN_DATEI = "angehefteter_stand.json"

# Hoechstfrist zwischen zwei Staenden (Z2-F5, #156). ZUSAGE, KEINE MESSGROESSE:
# entschieden von Werner am 04.08.2026, nicht aus dem Betrieb abgeleitet - sie
# bindet uns. Der Betriebsrhythmus ist woechentlich (docs/VERZEICHNIS.md,
# Abschnitt Betrieb); 14 Tage lassen einen ausgefallenen Lauf durchgehen und
# machen den zweiten zum Befund. Wer sie aendert, aendert eine oeffentliche
# Zusage und traegt sie in docs/VERZEICHNIS.md nach.
#
# Warum das hier steht und nicht im Verifier: der Verifier hat bewusst keine
# Uhr - er soll offline und reproduzierbar sein, dieselbe Eingabe muss immer
# dasselbe Urteil ergeben. Frische ist aber eine Aussage ueber JETZT. Sie
# gehoert deshalb zum Beobachter, der ohnehin eine Uhr hat und dessen Rolle
# genau das Hinsehen ueber die Zeit ist.
MAX_STAND_ABSTAND_STUNDEN = 336  # 14 Tage

# Obergrenzen: ein Beobachter laedt von einer Stelle, der er gerade NICHT
# vertraut. Eine Antwort ohne Grenze waere ein Hebel gegen ihn.
MAX_DATEI = 32 * 1024 * 1024
MAX_GESAMT = 256 * 1024 * 1024
MAX_DATEIEN = 5000
TIMEOUT = 60


class AbholFehler(Exception):
    """Der Abzug liess sich nicht vollstaendig holen."""


def _jetzt() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _stempel() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _als_zeit(wert: object) -> Optional[float]:
    """Z-Zeitstempel als Sekunden seit der Epoche; None, wenn unlesbar."""
    if not isinstance(wert, str) or not wert:
        return None
    try:
        return calendar.timegm(time.strptime(wert.strip(), "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None


def alter_des_standes(stand_created_at: object) -> Optional[float]:
    """Stunden zwischen dem juengsten Stand und JETZT; None, wenn unlesbar."""
    dann = _als_zeit(stand_created_at)
    if dann is None:
        return None
    return (time.time() - dann) / 3600.0


def koepfe_zeiten(abzug: str) -> List[Tuple[str, str]]:
    """(kopf_nr, created_at) aller Koepfe im geholten Abzug, aufsteigend.

    Reines Lesen aus Dateien, die der Verifier IM SELBEN LAUF geprueft hat
    (V4: Kette, Signatur und Wurzel je Kopf). Der Beobachter bringt damit
    weiterhin keine eigene Kryptographie mit - er liest ein Feld aus etwas,
    das eben nachgerechnet wurde.
    """
    ordner = os.path.join(abzug, "koepfe")
    aus: List[Tuple[str, str]] = []
    if not os.path.isdir(ordner):
        return aus
    for name in sorted(os.listdir(ordner)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(ordner, name), "r", encoding="utf-8") as fh:
                kopf = json.load(fh)
        except (OSError, ValueError):
            continue
        aus.append((str(kopf.get("kopf_nr")), kopf.get("created_at")))
    aus.sort(key=lambda p: int(p[0]) if p[0].isdigit() else 0)
    return aus


def verzug_zwischen_staenden(
    zeiten: List[Tuple[str, str]],
    ab_kopf_nr: Optional[str],
    frist_stunden: float = MAX_STAND_ABSTAND_STUNDEN,
) -> List[str]:
    """Die Zusage gilt ZWISCHEN zwei Staenden, nicht nur am Ende.

    Ohne diese Haelfte faengt die Frist nur den stehengebliebenen Schwanz:
    wer drei Wochen schweigt und dann zwei Staende auf einmal nachschiebt,
    haette am Ende einen frischen Kopf und die Zusage trotzdem gebrochen.

    Gerechnet wird **ab dem angehefteten Stand**, nicht ueber die ganze
    Geschichte. Zwei Gruende: die Zusage gilt ab ihrer Veroeffentlichung und
    nicht rueckwirkend, und der Beobachter sagt ohnehin nur ueber die Zeit
    aus, in der er hingesehen hat. Ohne angehefteten Stand gibt es hier
    nichts zu sagen - das ist der erste Lauf.
    """
    if ab_kopf_nr is None:
        return []
    beginn = None
    for i, (nr, _) in enumerate(zeiten):
        if nr == str(ab_kopf_nr):
            beginn = i
            break
    if beginn is None:
        return []
    befunde: List[str] = []
    strecke = zeiten[beginn:]
    for (nr_a, zeit_a), (nr_b, zeit_b) in zip(strecke, strecke[1:]):
        a, b = _als_zeit(zeit_a), _als_zeit(zeit_b)
        if a is None or b is None:
            befunde.append(
                f"zwischen Kopf {nr_a} und {nr_b} laesst sich der Abstand nicht rechnen "
                f"({zeit_a!r} -> {zeit_b!r}) - ungerechnet ist die Frist kein Freispruch")
            continue
        abstand = (b - a) / 3600.0
        if abstand > frist_stunden:
            befunde.append(
                f"zwischen Kopf {nr_a} ({zeit_a}) und Kopf {nr_b} ({zeit_b}) liegen "
                f"{abstand / 24:.1f} Tage - mehr als die zugesagten "
                f"{frist_stunden / 24:.0f}")
    return befunde


def verzug(stand_created_at: object,
           frist_stunden: float = MAX_STAND_ABSTAND_STUNDEN) -> Optional[str]:
    """Ist die zugesagte Hoechstfrist ueberschritten? Dann der Befundtext.

    Der Punkt aus #156: Luecken INNERHALB der Folge faengt V2, ein
    stehengebliebener Schwanz nicht. Ein eingefrorenes oder am Ende
    abgeschnittenes Verzeichnis besteht jede einzelne Pruefung - es ist ja in
    sich stimmig - und damit bestuende A2 (der still ausgelassene Lauf) am
    Verzeichnis selbst, also an der Antwort auf A2. Wer unbequeme Staende nicht
    faelscht, sondern das Veroeffentlichen einstellt, faellt sonst niemandem
    auf.

    Vorbild ist die maximale Merge-Verzoegerung der Certificate Transparency:
    ein Log, das laenger als zugesagt nichts anhaengt, ist im Verzug, und der
    Verzug ist ein Befund - kein Bruch der Kette, aber auch kein Freispruch.

    Ein unlesbares oder fehlendes created_at ist ausdruecklich KEIN stiller
    Freispruch: dann laesst sich die Frist nicht rechnen, und genau das wird
    gemeldet.
    """
    if _als_zeit(stand_created_at) is None:
        return (f"der juengste Stand nennt kein lesbares created_at "
                f"({stand_created_at!r}) - die zugesagte Hoechstfrist von "
                f"{frist_stunden:.0f} h laesst sich damit nicht rechnen, und "
                "ungerechnet ist sie kein Freispruch")
    alter = alter_des_standes(stand_created_at)
    if alter is None or alter <= frist_stunden:
        return None
    return (f"der juengste Stand ist vom {stand_created_at} und damit "
            f"{alter / 24:.1f} Tage alt. Zugesagt sind hoechstens "
            f"{frist_stunden / 24:.0f} Tage ({frist_stunden:.0f} h, "
            "docs/VERZEICHNIS.md). Das Verzeichnis ist im VERZUG: es ist in sich "
            "stimmig, aber es waechst nicht mehr. Ein Verzeichnis, das stehen "
            "bleibt, ist genau die Luecke, die es schliessen soll")


# ------------------------------------------------------------------ abholen

def _pfad_ist_harmlos(rel: str) -> bool:
    """Nur einfache relative Pfade; kein '..', kein absoluter Pfad, kein Trick."""
    if not rel or rel.startswith(("/", "\\")) or ":" in rel:
        return False
    teile = rel.replace("\\", "/").split("/")
    return all(t and t not in (".", "..") for t in teile) and len(teile) <= 3


def _hole_http(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "phm-beobachter/1"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as antwort:
            if getattr(antwort, "status", 200) != 200:
                raise AbholFehler(f"{url}: HTTP {antwort.status}")
            daten = antwort.read(MAX_DATEI + 1)
    except urllib.error.URLError as e:
        raise AbholFehler(f"{url}: nicht erreichbar ({e})")
    if len(daten) > MAX_DATEI:
        raise AbholFehler(f"{url}: groesser als die Obergrenze von {MAX_DATEI} Byte")
    return daten


def _hole_datei(quelle: str, rel: str) -> bytes:
    if quelle.startswith(("http://", "https://")):
        return _hole_http(urllib.parse.urljoin(quelle.rstrip("/") + "/", rel))
    pfad = os.path.join(quelle, rel)
    try:
        if os.path.getsize(pfad) > MAX_DATEI:
            raise AbholFehler(f"{pfad}: groesser als die Obergrenze von {MAX_DATEI} Byte")
        with open(pfad, "rb") as fh:
            return fh.read()
    except OSError as e:
        raise AbholFehler(f"{pfad}: nicht lesbar ({e})")


def hole_abzug(quelle: str, ziel: str) -> List[str]:
    """
    Holt verzeichnis.jsonl und alles, was INHALT.txt auflistet, nach ziel.
    Liefert die Liste der geholten relativen Pfade.
    """
    if quelle.startswith(("http://", "https://")):
        pass
    elif not os.path.isdir(quelle):
        raise AbholFehler(f"{quelle}: kein Ordner und keine http(s)-Adresse")
    os.makedirs(ziel, exist_ok=True)

    try:
        inhalt_roh = _hole_datei(quelle, INHALT_DATEI).decode("utf-8")
    except (AbholFehler, UnicodeDecodeError):
        # Ohne INHALT.txt bleibt der Pflichtteil: die Datei selbst. Koepfe
        # und Anker fehlen dann, und der Verifier sagt das laut (er
        # verlangt mindestens einen Kopf) - kein stiller Teilabzug.
        inhalt_roh = VERZEICHNIS_DATEI
    namen = [z.strip() for z in inhalt_roh.splitlines() if z.strip() and not z.startswith("#")]
    if VERZEICHNIS_DATEI not in namen:
        namen.insert(0, VERZEICHNIS_DATEI)
    if len(namen) > MAX_DATEIEN:
        raise AbholFehler(f"INHALT.txt listet {len(namen)} Dateien - ueber der Obergrenze")

    geholt: List[str] = []
    gesamt = 0
    for rel in namen:
        if not _pfad_ist_harmlos(rel):
            raise AbholFehler(f"INHALT.txt nennt einen unzulaessigen Pfad: {rel!r}")
        daten = _hole_datei(quelle, rel)
        gesamt += len(daten)
        if gesamt > MAX_GESAMT:
            raise AbholFehler(f"Abzug groesser als die Obergrenze von {MAX_GESAMT} Byte")
        pfad = os.path.join(ziel, rel)
        os.makedirs(os.path.dirname(pfad) or ziel, exist_ok=True)
        with open(pfad, "wb") as fh:
            fh.write(daten)
        geholt.append(rel)
    return geholt


# ------------------------------------------------------------------ pruefen

def finde_verifier(vorgabe: Optional[str]) -> str:
    if vorgabe:
        if not os.path.isfile(vorgabe):
            raise AbholFehler(f"--verifier {vorgabe}: Datei nicht gefunden")
        return vorgabe
    neben = os.path.join(os.path.dirname(os.path.abspath(__file__)), VERIFIER)
    if not os.path.isfile(neben):
        raise AbholFehler(
            f"{VERIFIER} liegt nicht neben diesem Skript. Beide gehoeren zusammen: "
            "dieses holt ab, jenes prueft. Pfad mit --verifier angeben."
        )
    return neben


def pruefe(
    verifier: str,
    abzug: str,
    pin: Optional[str],
    tsa_certs: Optional[List[str]],
    public_key: Optional[str],
    key_history: Optional[str] = None,
) -> Tuple[int, dict, str]:
    """Setzt phm_verifier.py auf den Abzug an. Liefert (exit, ergebnis, klartext)."""
    grund = [sys.executable, verifier, abzug]
    if pin and os.path.isfile(pin):
        grund += ["--pin", pin]
    for cert in tsa_certs or []:
        grund += ["--tsa-cert", cert]
    if public_key:
        grund += ["--public-key", public_key]
    # Ohne dieses Durchreichen wurde --key-history stillschweigend geschluckt:
    # die Option stand im Hilfetext, kam aber nie beim Verifier an, und der
    # Beobachter prueft dann trotzdem "erfolgreich" - ohne Historie.
    if key_history:
        grund += ["--key-history", key_history]
    lauf = subprocess.run(grund + ["--json"], capture_output=True, text=True)
    try:
        ergebnis = json.loads(lauf.stdout)
    except ValueError:
        raise AbholFehler(
            "der Verifier hat kein JSON geliefert (Exit "
            f"{lauf.returncode}): {(lauf.stderr or lauf.stdout)[:400]}"
        )
    klartext = subprocess.run(grund, capture_output=True, text=True).stdout
    return lauf.returncode, ergebnis, klartext


# ------------------------------------------------------- Gedaechtnis (Pin)

def lade_verifier(pfad: str) -> Any:
    """
    phm_verifier.py als Modul, fuer die Anheft-Logik (E20, #354).

    Geprueft wird weiterhin im Unterprozess (pruefe()); geladen wird hier nur,
    was Verifier und Beobachter teilen muessen: Pin schreiben, Protokoll
    fortschreiben, Gedaechtnisluecke erkennen. Eine eigene Kopie hier waere
    die zweite Umsetzung, die mit der Zeit abweicht. Ein Verifier, der diese
    Funktionen nicht kennt (aelter als E20), ist ein unbrauchbarer Lauf
    (Exit 2), kein Rueckfall auf eine eigene Fassung.
    """
    spec = importlib.util.spec_from_file_location("phm_verifier_fuer_beobachter", pfad)
    if spec is None or spec.loader is None:
        raise AbholFehler(f"{pfad}: nicht als Python-Modul ladbar")
    modul = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(modul)
    except Exception as e:  # jede Ladestoerung ist ein unvollstaendiger Lauf
        raise AbholFehler(f"{pfad}: nicht ladbar ({e.__class__.__name__}: {e})")
    fehlend = [n for n in ("gedaechtnisluecke", "hefte_an", "beobachtungen_neben")
               if not hasattr(modul, n)]
    if fehlend:
        raise AbholFehler(
            f"{pfad} kennt {', '.join(fehlend)} nicht - der Verifier ist aelter als dieser "
            "Beobachter (E20). Beide aus demselben Stand beziehen.")
    return modul


def melde_gedaechtnisluecke(ablage: str, stempel: str, quelle: str, luecke: dict) -> int:
    """Schreibt den Bericht und meldet den Fehlschlag. Es wird nichts geholt."""
    bericht = {
        "beobachtet_at": _jetzt(),
        "quelle": quelle,
        "abzug": None,
        "dateien": [],
        "verifier": None,
        "verifier_exit": None,
        "angehefteter_stand": None,
        "ergebnis": luecke,
    }
    name = os.path.join(ablage, f"BRUCH_{stempel}.json")
    with open(name, "w", encoding="utf-8") as fh:
        json.dump(bericht, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    print("=== BRUCH: GEDAECHTNISLUECKE BEIM BEOBACHTER ===")
    print(luecke["grund"])
    print(f"Abhilfe: {luecke['abhilfe']}")
    print(f"Bericht: {name}")
    print("Es wurde nichts geholt und nichts geprueft: dieser Lauf haette "
          "keine Aussage tragen koennen.")
    return 1


# ------------------------------------------------------------------ Lauf

def lauf(args: argparse.Namespace) -> int:
    ablage = os.path.abspath(args.ablage)
    os.makedirs(ablage, exist_ok=True)
    pin = os.path.join(ablage, PIN_DATEI)
    stempel = _stempel()
    abzug = os.path.join(ablage, "abzuege", stempel)

    # Der Verifier zuerst: er traegt auch die Anheft-Logik (E20). Ohne ihn
    # laesst sich nicht einmal das eigene Gedaechtnis beurteilen.
    try:
        verifier = finde_verifier(args.verifier)
        V = lade_verifier(verifier)
    except AbholFehler as e:
        print(f"UNVOLLSTAENDIGER LAUF: {e}", file=sys.stderr)
        print("Das ist kein Freispruch: es wurde nichts geprueft.", file=sys.stderr)
        return 2

    # Vor dem Abholen: taugt das eigene Gedaechtnis ueberhaupt als Bezugspunkt?
    luecke = V.gedaechtnisluecke(pin)
    if luecke is not None:
        return melde_gedaechtnisluecke(ablage, stempel, args.von, luecke)

    try:
        geholt = hole_abzug(args.von, abzug)
    except AbholFehler as e:
        print(f"UNVOLLSTAENDIGER LAUF: {e}", file=sys.stderr)
        print("Das ist kein Freispruch: es wurde nichts geprueft.", file=sys.stderr)
        return 2

    hatte_pin = os.path.isfile(pin)
    try:
        # Direkter Zugriff, kein getattr mit Default (#160). Die Option ist
        # unten immer deklariert; ein getattr haette ein Umbenennen zu einem
        # stillen None gemacht - dieselbe Fehlerklasse, gegen die die Zeile
        # daneben gebaut ist. Ein Default auf einem garantiert vorhandenen
        # Attribut ist eine eingebaute stille Rueckfallebene.
        code, ergebnis, klartext = pruefe(
            verifier, abzug, pin if hatte_pin else None, args.tsa_cert, args.public_key,
            args.key_history,
        )
    except AbholFehler as e:
        print(f"UNVOLLSTAENDIGER LAUF: {e}", file=sys.stderr)
        return 2

    print(klartext or json.dumps(ergebnis, ensure_ascii=False, indent=2))
    print(f"Beobachtet: {_jetzt()}, Quelle {args.von}, {len(geholt)} Datei(en), Abzug {abzug}")
    if not hatte_pin:
        print("HINWEIS: es lag noch kein angehefteter Stand vor - dieser Lauf konnte nur "
              "pruefen, ob der Abzug in sich stimmt. Die Aussage entsteht ab dem naechsten Lauf.")

    alter_stand = None
    if hatte_pin:
        with open(pin, "r", encoding="utf-8") as fh:
            alter_stand = json.load(fh)
    bericht = {
        "beobachtet_at": _jetzt(),
        "quelle": args.von,
        "abzug": abzug,
        "dateien": geholt,
        "verifier": verifier,
        "verifier_exit": code,
        "angehefteter_stand": alter_stand,
        "ergebnis": ergebnis,
    }

    if ergebnis.get("passed"):
        neuer = dict(ergebnis.get("neuer_pin") or {})
        neuer["beobachtet_at"] = bericht["beobachtet_at"]
        neuer["quelle"] = args.von
        eintrag = {k: bericht[k] for k in ("beobachtet_at", "quelle", "verifier_exit")}
        eintrag["stand"] = neuer.get("kopf_nr")
        eintrag["zeilen"] = ergebnis.get("zeilen")
        # Pin und Protokollzeile in EINEM Vorgang aus dem Verifier (E20):
        # write-once, atomar ersetzt, erst der Pin, dann die Zeile.
        V.hefte_an(pin, neuer, eintrag)
        gut = os.path.join(ablage, "letzter_guter_abzug")
        shutil.rmtree(gut, ignore_errors=True)
        shutil.copytree(abzug, gut)
        print(f"Stand angeheftet: Kopf {neuer.get('kopf_nr')} ({neuer.get('tree_size')} Zeilen).")

        # Z2-F5 (#156): die Pruefung ist bestanden, der Abzug ist in sich
        # stimmig - und genau deshalb steht die Frage nach der Frische ERST
        # hier. Ein eingefrorenes Verzeichnis besteht jede einzelne Pruefung.
        befunde = []
        am_ende = verzug(neuer.get("stand_created_at"))
        if am_ende:
            befunde.append(am_ende)
        # Und die andere Haelfte: die Zusage gilt ZWISCHEN zwei Staenden. Wer
        # drei Wochen schweigt und dann zwei Koepfe nachschiebt, haette am Ende
        # einen frischen Stand und die Zusage trotzdem gebrochen.
        dazwischen = verzug_zwischen_staenden(
            koepfe_zeiten(abzug), (alter_stand or {}).get("kopf_nr"))
        befunde.extend(dazwischen)

        if not befunde:
            alter = alter_des_standes(neuer.get("stand_created_at"))
            if alter is not None:
                print(f"Frist eingehalten: der juengste Stand ist {alter / 24:.1f} Tage alt "
                      f"(zugesagt hoechstens {MAX_STAND_ABSTAND_STUNDEN / 24:.0f}), und seit "
                      "Ihrem angehefteten Stand liegt zwischen zwei Koepfen keine groessere "
                      "Luecke.")
            return 0

        bericht["verzug"] = {
            "befunde": befunde,
            "am_ende": am_ende,
            "zwischen_staenden": dazwischen,
            "stand_created_at": neuer.get("stand_created_at"),
            "frist_stunden": MAX_STAND_ABSTAND_STUNDEN,
            "alter_stunden": alter_des_standes(neuer.get("stand_created_at")),
        }
        name = os.path.join(ablage, f"VERZUG_{stempel}.json")
        with open(name, "w", encoding="utf-8") as fh:
            json.dump(bericht, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        print()
        print("=== VERZUG ===")
        for eintrag in befunde:
            print("- " + eintrag + ".")
        print(f"Bericht: {name}")
        print("Das ist KEIN Bruch der Kette: alles, was veroeffentlicht wurde, ist "
              "vertraeglich. Es ist die andere Haelfte - es wird nichts mehr "
              "veroeffentlicht.")
        print("Melden an: den Betreiber. Bleibt es dabei, ist die Zusage gebrochen.")
        return 3

    name = os.path.join(ablage, f"BRUCH_{stempel}.json")
    with open(name, "w", encoding="utf-8") as fh:
        json.dump(bericht, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    print()
    print("=== BRUCH ODER FEHLER ===")
    print(f"Bericht: {name}")
    print(f"Beleg:   der geholte Abzug unter {abzug} und der bisher angeheftete Stand "
          f"({pin}) - beide unveraendert aufbewahren.")
    print("Der angeheftete Stand wurde NICHT fortgeschrieben.")
    print("Melden an: den Betreiber und, wenn es um eine Pruefung geht, an den, "
          "der sich auf den Nachweis stuetzt.")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Holt das oeffentliche PHM-Wurzelverzeichnis ab, laesst es pruefen "
                    "und meldet einen Bruch.",
        epilog="Beschreibung der Rolle: docs/VERZEICHNIS.md",
    )
    p.add_argument("--von", required=True,
                   help="http(s)-Adresse oder Pfad des veroeffentlichten Verzeichnisses")
    p.add_argument("--ablage", default="beobachtung",
                   help="Ordner fuer angehefteten Stand, Abzuege und Berichte "
                        "(Vorgabe: ./beobachtung)")
    p.add_argument("--verifier", help=f"Pfad zu {VERIFIER} (Vorgabe: neben diesem Skript)")
    p.add_argument("--tsa-cert", action="append",
                   help="Vertrauenszertifikat einer Zeitstempelstelle (mehrfach moeglich)")
    p.add_argument("--public-key",
                   help="einzelner oeffentlicher Ed25519-Schluessel (Hex). Bricht bei einer "
                        "Schluesselrotation ab, weil aeltere Koepfe die alte key_id tragen - "
                        "besser --key-history")
    p.add_argument("--key-history",
                   help="veroeffentlichte Schluesselhistorie (JSON): loest je Kopf ueber die "
                        "key_id auf, prueft das Gueltigkeitsfenster und verlangt, dass ein "
                        "Schluesselwechsel in der Kopf-Kette erklaert ist. Ohne beides bezeugt "
                        "sich der Abzug in diesem Punkt selbst")
    return lauf(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
