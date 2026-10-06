#!/usr/bin/env python3
"""
PHM-Siegel-Verifier (S4): eigenstaendiges Pruefwerkzeug fuer exportierte
Aufzeichnungspakete. Benutzung fuer Pruefer: docs/VERIFIKATION.md.
Formate: docs/SIEGEL_UMSCHLAG.md (Umschlag), docs/SIEGEL_VERSIEGELUNG.md
(Siegel und Baum), docs/SIEGEL_ANKER.md (RFC-3161-Anker).

Unabhaengigkeits-Regel (Issue #29): dieses Skript ist EINE Datei, braucht nur
Python 3.8 oder neuer (Standardbibliothek, keine Zusatzpakete), importiert
nichts aus dem PHM-Repository und spricht weder mit unserem Server noch mit
unserer Datenbank noch mit dem Netz. Alles Noetige liegt im Paket selbst
beziehungsweise in oeffentlich pruefbaren Zertifikaten, die der Pruefer
vorlegt. Die Serialisierungs- und Pruefregeln sind hier bewusst ein zweites
Mal implementiert (nicht importiert), damit ein gemeinsamer Fehler von
Erzeuger und Pruefer unwahrscheinlicher wird; die Spezifikationen oben sind
die Referenz.

Was geprueft wird (je Schritt bestanden / nicht bestanden / uebersprungen):
  0. BagIt-Ablage (RFC 8493), wenn die Eingabe ein Verzeichnis ist: jede
     Manifest-Prueffsumme nachgerechnet, Vollstaendigkeit unter data/ gegen
     manifest-sha256.txt und Vollstaendigkeit der Bag-Wurzel gegen
     tagmanifest-sha256.txt (V5-F3, #166: eine Datei neben data/ fiel
     vorher unter kein Manifest). Fehlt das Tagmanifest, zaehlt der
     Befundtext die ungedeckten Dateien der Wurzel auf.
     Die Prueffsummen rechnet auch ohne dieses Skript nach, wer beide
     Zeilen faehrt (shasum -a 256 --check manifest-sha256.txt UND
     tagmanifest-sha256.txt, #165). Die Vollstaendigkeit nicht: was in
     den Listen fehlt, faellt `--check` nicht auf (V5-F4, #167).
  1. Umschlag: kanonische Serialisierung reproduzieren, SHA-256 nachrechnen,
     Payload-Hash gegen die Payload-Bytes halten.
  1a. Inhaltsdatei (ap14, Gate-A-Befund S2a/S2b): liegt neben dem Paket die
     Datei, unter deren Namen der versiegelte Umschlag die Nutzlast fuehrt
     (letztes Glied von payload.reference, etwa KRITERIENWERK.md oder
     akte.json), wird sie Byte fuer Byte gegen payload.sha256 und
     payload_b64 gehalten. Abweichung ist ein Fehler. In einer Ablage: jede
     gleichnamige Datei unter data/ (Gross-/Kleinschreibung egal), und die
     Datei MUSS unter data/<name> liegen, wenn das Paket payload_b64 traegt;
     eine Paketdatei, die nicht direkt unter data/ liegt, ist ein Befund in
     Schritt 0. Bei der nackten Paketdatei: fehlt die Datei daneben, ist der
     Schritt uebersprungen ("NICHT GEMESSEN, Datei fehlt") und das Merkmal
     in der Feststellungsliste offen. Vorher war nur die Kopie im Paket
     gebunden, nicht die Datei, die gelesen wird.
  1b. Auslieferung (S6/A5, #116): jede neben dem Paket gelieferte Datei gegen
     die MITVERSIEGELTE Liste im Umschlag. Veraendert, fehlend und
     zusaetzlich sind drei Befunde, alle drei sind Fehler. Fuehrt der
     Umschlag keine Liste, wird der Schritt uebersprungen, nie still gruen.
  1c. Nachgelagerte Liste (S6-F1, #144): die Dateien, die erst NACH dem
     Siegeln entstehen, gegen data/nachtrag.json - eine zweite, vom Erzeuger
     signierte Liste. Vom Siegel ist sie nicht gedeckt, sie entsteht danach;
     sie bindet die Dateien an den Erzeuger und an dieses Siegelpaket. Nur
     was sie fuehrt, nimmt 1b aus - vorher gab es dort eine unbedingte
     Ausnahme fuer einen festen Dateinamen, und die war eine Luecke.
  1d. Archiv-Zugehoerigkeitsnachweis: liegt data/archiv_nachweis.json bei,
     wird er hier geprueft - und zwar auch daraufhin, ob er von DIESEM Paket
     handelt (Prueffsumme des Siegelpakets in der Index-Zeile). Mit
     --archiv-public-key gegen den vorgelegten Manifest-Schluessel, sonst
     gegen den im Nachweis (ehrlich ausgewiesen).
     Die Schritte 1b bis 1d laufen nach 3, weil sie den geprueften Umschlag
     brauchen; die Nummer sagt, wohin sie gehoeren, nicht wann sie fahren.
  0b. bag-info.txt (S6-F3, #149): die inhaltlichen Angaben der Bag-Wurzel
     (PHM-Stichtag und die uebrigen PHM-Felder) gegen den versiegelten
     Umschlag. Sie liegen ausserhalb von data/ und damit ausserhalb der
     Auslieferungsliste, sind aber Kopien versiegelter Werte.
  2. Siegel: signierte Serialisierung reproduzieren, seal_hash nachrechnen.
  3. Signatur (Ed25519, RFC 8032): gegen den OEFFENTLICHEN Schluessel.
     Der Pruefer legt ihn selbst vor (--public-key, aus der veroeffentlichten
     Schluesselhistorie); ohne Vorlage wird der Schluessel aus dem Paket
     genommen und das ehrlich ausgewiesen (das Paket bezeugt sich dann in
     diesem Punkt selbst). 3b haelt Paket-Schluessel und vorgelegten
     Schluessel gegeneinander.
  4. Zeitstempel-Token (RFC 3161): messageImprint gegen den NACHGERECHNETEN
     seal_hash, dann die TSA-Signatur ueber dem Token vollstaendig pruefen
     (CMS SignedData: messageDigest, contentType, ESSCertID, Signatur mit dem
     Schluessel aus dem Signer-Zertifikat; RSA PKCS#1 v1.5 und ECDSA P-256/
     P-384 mit SHA-256/384/512). Mit --tsa-cert wird das Signer-Zertifikat
     zusaetzlich gegen das vorgelegte Vertrauenszertifikat gehalten.
  5. Baum: jedes Blatt nachgerechnet, Blatt-Positionen, Fortschreibung der
     Wurzel (jedes Siegel signiert die Wurzel ueber seine Vorgaenger), und
     dass das gepruefte Siegel an seiner Position im Baum steht.
  6. Zugehoerigkeitsnachweis (Merkle-Pfad, RFC 6962): das einzelne Siegel
     wird ueber den mitgelieferten Pfad zur angegebenen Wurzel gefuehrt -
     pruefbar, ohne dass der uebrige Bestand im Paket liegen muss.

ZWEITER EINGABETYP: Archiv-Zugehoerigkeitsnachweis (Z1 Teil 2, #39/#66).
Statt eines Siegel-Pakets nimmt dasselbe Skript ein Nachweis-Paket
(package_type "phm-archiv-nachweis", erzeugt mit
tools/archiv_wurzel.py --nachweis ENTRY_ID --paket DATEI). Belegt wird
damit, dass EIN Dokument zu einem extern bezeugten Archivbestand
gehoerte, ohne die Dokumente anderer offenzulegen:
  A1.  Index-Zeile: SHA-256 ueber die rohen Zeilen-Bytes = Blatt-Eingabe.
  A1b. Mit --dokument: die vorgelegte Datei gegen die Prueffsumme IN der
       Index-Zeile (bindet die Datei an die Zeile).
  A2.  Merkle-Pfad (RFC 6962) vom Blatt zur Wurzel.
  A3.  Wochen-Manifest ueber der Wurzel: signierte Serialisierung,
       Ed25519-Signatur, manifest_hash, key_id im Raum "am-".
  A4.  Externer Anker (RFC 3161) auf die WURZEL, volle CMS-Pruefung wie
       in Schritt 4; ohne Anker ist die Zugehoerigkeit belegt, ein
       Zeitpunkt nicht.
  A5.  Datensparsamkeit: nur die eigene Zeile und Knoten-Hashes im Paket,
       unbekannte Felder sind ein Befund.
Was auch dieser Nachweis NICHT zeigt: dass der Bestand vollstaendig ist.
Ein nie archiviertes Dokument fehlt unbemerkt (docs/ARCHIV.md).

DRITTER EINGABETYP: Verzeichnis-Abzug (Z2, #81). Der Ordner, wie er
veroeffentlicht wird (verzeichnis.jsonl + koepfe/ + anker/). Hier wird
nicht EIN Nachweis geprueft, sondern der veroeffentlichte BESTAND ueber
die Zeit beobachtet:
  V1. Zeilenkette: kanonische Form, Nummernfolge, prev-Verkettung.
  V2. Die veroeffentlichten Wochen-Manifeste (Ed25519, Kette, Monotonie).
  V3. Die veroeffentlichten Anker (RFC 3161) auf die jeweilige Wurzel,
      und die behauptete Entstehungszeit gegen die bezeugte gehalten.
  V4. Koepfe: Kette, Signatur, jede Wurzel aus den Zeilen nachgerechnet.
  V5. Mit --pin: der frueher angeheftete Stand muss unveraendertes
      Anfangsstueck des heutigen sein (Konsistenz, RFC 6962 2.1.4), UND
      sein Schluessel muss zum heutigen Abzug passen - ein Wechsel nur,
      wenn er erklaert ist. OHNE diesen Vergleich ist ein Abzug nur in
      sich stimmig, und die mitgelieferte Schluesselhistorie bezeugt sich
      selbst.
  V6. Datensparsamkeit: nur Wurzeln, unbekannte Felder sind ein Befund.
  V7. Die Anker (RFC 3161) auf die KOEPFE, und auch hier die behauptete
      Entstehungszeit gegen die bezeugte.
Mit --anheften wird der gepruefte Stand aufbewahrt (nur bei bestandener
Pruefung), write-once wie beim Beobachter und aus derselben Funktion (E20):
0444, fortgeschrieben nur durch atomares Ersetzen, ein Protokoll
(beobachtungen.jsonl) daneben, jede Zeile mit dem Pin-Namen, und ein
fehlender Pin, fuer den das Protokoll fruehere Anheftungen ausweist, ist ein
Bruch (Exit 1), kein Neuanfang. Ein vorhandener Pin wird
nur nach dem Vergleich mit genau ihm (--pin derselben Datei) fortgeschrieben.
Ein Konsistenz-Paket (paket_typ "phm-verzeichnis-konsistenz")
wird ebenfalls erkannt und allein geprueft:
  K1. Echtheit beider Staende - das Paket traegt die beiden KOEPFE im
      Original, die Signatur ist die der Instanz, nicht die des
      Uebermittlers (Paketversion 2).
  K2. Vertraeglichkeit der beiden Staende (RFC 6962 2.1.4).
Das ist das Austauschformat zwischen zwei Beobachtern: wer es weitergibt,
reicht weiter, was er bekommen hat, statt etwas Neues zu behaupten.
DIE GRENZE, DIE HIER ZAEHLT: das Verzeichnis ist eine ZUSAETZLICHE
Aussage (Vollstaendigkeit im Sinne von "alle sehen dasselbe"), niemals
eine Voraussetzung. Die Schritte 0-6 und A1-A5 laufen ohne Verzeichnis,
ohne Netz und ohne uns.

Versionsbewusstsein (Issue #29): die kanonische Serialisierung ist JE
VERSION implementiert (Umschlag v1 und v2); ein Siegel auf Version 1
bleibt auch nach Einfuehrung von Version 2 pruefbar, und das Ergebnis
weist aus, gegen welche Version geprueft wurde (envelope_version/
seal_version im JSON, Versionen-Zeile im Klartext). Fuer den zweiten
Eingabetyp gilt dasselbe: package_version des Nachweises und
manifest_version werden geprueft und ausgewiesen, aeltere Nachweise
bleiben pruefbar.

Was das Gesamturteil bedeutet und was nicht: ein bestandenes Paket belegt
Existenz (spaetestens zum TSA-Zeitpunkt), Unveraendertheit, Urheberschaft
(Signatur) und Reihenfolge der Aufzeichnung. Es belegt NICHT, dass der
Inhalt fachlich richtig ist.

Aufruf (AKTE = BagIt-Verzeichnis, nackte Paketdatei, Nachweis-Paket,
Verzeichnis-Abzug oder Konsistenz-Paket):
  python3 phm_verifier.py AKTE [--tsa-cert ZERTIFIKAT.pem]
                          [--public-key HEX | --public-key-file DATEI]
                          [--dokument DATEI] [--pin PIN.json]
                          [--anheften PIN.json] [--json]

Ausgabe auf stdout, Exit-Code 0 = alle durchgefuehrten Pruefungen bestanden,
1 = mindestens eine Pruefung nicht bestanden, 2 = Paket/Aufruf unbrauchbar.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import unicodedata
from typing import Any, Dict, List, Optional, Sequence, Tuple

PACKAGE_VERSION = "1"
PACKAGE_TYPE = "phm-siegel-paket"

# Serialisierung je Version implementiert, nicht ersetzt (Issue #26,
# Statusklaerung 30.07.): v1-Pakete bleiben pruefbar, v2 ergaenzt additiv.
ENVELOPE_VERSIONS = ("1", "2")
SEAL_VERSION = "1"
SEAL_SIG_ALGO = "ed25519"
SEAL_HASH_ALGO = "sha256"
# Wurzel des leeren Baums (RFC 6962): SHA-256 ueber die leere Eingabe.
EMPTY_TREE_ROOT = hashlib.sha256(b"").hexdigest()

_TS_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ED25519_SIG_RE = re.compile(r"^[0-9a-f]{128}$")
_LEAF_INDEX_RE = re.compile(r"^(0|[1-9]\d*)$")
# Algorithmuskennung (v2): Digest-Felder tragen ihr Verfahren als Praefix.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

BESTANDEN = "bestanden"
NICHT_BESTANDEN = "nicht bestanden"
UEBERSPRUNGEN = "uebersprungen"


class PaketFehler(ValueError):
    """Das Paket selbst ist unlesbar oder strukturell unbrauchbar (Exit 2)."""


class PruefungGescheitert(ValueError):
    """Eine inhaltliche Pruefung ist nicht bestanden (Begruendung in args[0])."""


# ===========================================================================
# Teil 1: Umschlag v1/v2 (kanonische Serialisierung je Version, Referenz:
# docs/SIEGEL_UMSCHLAG.md). Zweitimplementierung, kein Import.
# ===========================================================================

_SUBJECT_FIELDS = ("system", "operator")
_PAYLOAD_FIELDS = ("reference", "sha256", "media_type", "size_bytes")
_METHOD_FIELDS = {
    "1": ("id", "version"),
    "2": ("id", "version", "config_digest", "environment_digest", "parameters"),
}
_PARAMETER_FIELDS = ("name", "value")
_INPUT_FIELDS = {
    "1": ("name", "reference"),
    "2": ("name", "reference", "data_class"),
}
_DATASET_FIELDS = ("id", "reference", "manifest_digest")
_SOURCE_DOCUMENT_FIELDS = ("sha256", "retrieved_at", "reference")
_AS_OF_FIELDS = ("timestamp", "positions_without_knowledge_time")
_ORIGIN_FIELDS = ("kind", "description")
_TOP_FIELDS = {
    "1": (
        "envelope_version",
        "subject",
        "created_at",
        "payload",
        "method",
        "inputs",
        "source_documents",
        "as_of",
        "origin",
    ),
    "2": (
        "envelope_version",
        "subject",
        "created_at",
        "payload",
        "method",
        "auftrag",
        "auslieferung",
        "inputs",
        "dataset",
        "source_documents",
        "as_of",
        "origin",
    ),
}


def _env_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or value == "":
        raise PruefungGescheitert(f"{field}: nicht-leerer String erwartet")
    return unicodedata.normalize("NFC", value)


def _env_reject_unknown(obj: Dict[str, Any], allowed: Sequence[str], field: str) -> None:
    unknown = set(obj) - set(allowed)
    if unknown:
        raise PruefungGescheitert(f"{field}: unbekannte Felder {sorted(unknown)}")


def _env_optional(out: Dict[str, Any], src: Dict[str, Any], name: str, prefix: str) -> None:
    if src.get(name) is not None:
        out[name] = _env_string(src[name], f"{prefix}.{name}")


def _env_digest(value: Any, field: str) -> str:
    v = _env_string(value, field)
    if not _DIGEST_RE.match(v):
        raise PruefungGescheitert(
            f"{field}: Format sha256:<64 Hex-Kleinbuchstaben> erwartet (Algorithmuskennung ist Pflicht)"
        )
    return v


def canonical_envelope_bytes(envelope: Any) -> bytes:
    """
    Kanonische Bytes eines Umschlags nach den Spec-Regeln 1-7: feste
    Feldreihenfolge, NFC, sortierte inputs, nur Ganzzahlen, created_at nur
    im Z-Format, optionale Felder weggelassen, JSON kompakt in UTF-8.
    Massgeblich sind die Regeln der Version, die der Umschlag deklariert
    (v1 oder v2); alles Abweichende wird abgewiesen, nie still repariert.
    """
    if not isinstance(envelope, dict):
        raise PruefungGescheitert("envelope: Objekt erwartet")
    version = envelope.get("envelope_version")
    if version not in ENVELOPE_VERSIONS:
        raise PruefungGescheitert(
            f"envelope_version: nur {list(ENVELOPE_VERSIONS)} werden von diesem Verifier getragen"
        )
    _env_reject_unknown(envelope, _TOP_FIELDS[version], "envelope")

    subject_in = envelope.get("subject")
    if not isinstance(subject_in, dict):
        raise PruefungGescheitert("subject: Objekt erwartet")
    _env_reject_unknown(subject_in, _SUBJECT_FIELDS, "subject")
    subject: Dict[str, Any] = {"system": _env_string(subject_in.get("system"), "subject.system")}
    _env_optional(subject, subject_in, "operator", "subject")

    created_at = envelope.get("created_at")
    if not (isinstance(created_at, str) and _TS_Z_RE.match(created_at)):
        raise PruefungGescheitert("created_at: nur das Format YYYY-MM-DDThh:mm:ssZ ist gueltig")

    payload_in = envelope.get("payload")
    if not isinstance(payload_in, dict):
        raise PruefungGescheitert("payload: Objekt erwartet")
    _env_reject_unknown(payload_in, _PAYLOAD_FIELDS, "payload")
    sha = _env_string(payload_in.get("sha256"), "payload.sha256")
    if not _SHA256_RE.match(sha):
        raise PruefungGescheitert("payload.sha256: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    payload: Dict[str, Any] = {
        "reference": _env_string(payload_in.get("reference"), "payload.reference"),
        "sha256": sha,
    }
    _env_optional(payload, payload_in, "media_type", "payload")
    size = payload_in.get("size_bytes")
    if size is not None:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PruefungGescheitert("payload.size_bytes: Ganzzahl >= 0 erwartet")
        payload["size_bytes"] = size

    method_in = envelope.get("method")
    if not isinstance(method_in, dict):
        raise PruefungGescheitert("method: Objekt erwartet")
    _env_reject_unknown(method_in, _METHOD_FIELDS[version], "method")
    method: Dict[str, Any] = {
        "id": _env_string(method_in.get("id"), "method.id"),
        "version": _env_string(method_in.get("version"), "method.version"),
    }
    if version != "1":
        if method_in.get("config_digest") is not None:
            method["config_digest"] = _env_digest(method_in["config_digest"], "method.config_digest")
        if method_in.get("environment_digest") is not None:
            method["environment_digest"] = _env_digest(
                method_in["environment_digest"], "method.environment_digest"
            )
        params_in = method_in.get("parameters")
        if params_in is not None:
            if not isinstance(params_in, list):
                raise PruefungGescheitert("method.parameters: Liste erwartet")
            params: List[Dict[str, str]] = []
            seen = set()
            for i, item in enumerate(params_in):
                if not isinstance(item, dict):
                    raise PruefungGescheitert(f"method.parameters[{i}]: Objekt erwartet")
                _env_reject_unknown(item, _PARAMETER_FIELDS, f"method.parameters[{i}]")
                name = _env_string(item.get("name"), f"method.parameters[{i}].name")
                if name in seen:
                    raise PruefungGescheitert(
                        f"method.parameters: Parameter {name!r} doppelt (je Parameter genau ein Wert)"
                    )
                seen.add(name)
                params.append(
                    {"name": name, "value": _env_string(item.get("value"), f"method.parameters[{i}].value")}
                )
            if params:
                params.sort(key=lambda r: r["name"])
                method["parameters"] = params

    # Auftragsbezug (MOD-3) und Auslieferungsliste (S6): beide additiv ab v2.
    # Der Verifier ist eine EIGENE Umsetzung derselben Spec; er muss jedes Feld
    # kennen, das der Erzeuger schreiben kann, sonst scheitert die kanonische
    # Serialisierung an einem Umschlag, der in Ordnung ist.
    auftrag_in = envelope.get("auftrag")
    auftrag: Optional[Dict[str, Any]] = None
    if auftrag_in is not None:
        if version == "1":
            raise PruefungGescheitert("auftrag: erst ab envelope_version 2")
        if not isinstance(auftrag_in, dict):
            raise PruefungGescheitert("auftrag: Objekt erwartet")
        _env_reject_unknown(auftrag_in, ("kennung", "fassung"), "auftrag")
        auftrag = {"kennung": _env_string(auftrag_in.get("kennung"), "auftrag.kennung")}
        _env_optional(auftrag, auftrag_in, "fassung", "auftrag")

    auslieferung_in = envelope.get("auslieferung")
    auslieferung: List[Dict[str, str]] = []
    if auslieferung_in is not None:
        if version == "1":
            raise PruefungGescheitert("auslieferung: erst ab envelope_version 2")
        if not isinstance(auslieferung_in, list):
            raise PruefungGescheitert("auslieferung: Liste erwartet")
        gesehen = set()
        for i, item in enumerate(auslieferung_in):
            if not isinstance(item, dict):
                raise PruefungGescheitert(f"auslieferung[{i}]: Objekt erwartet")
            _env_reject_unknown(item, ("pfad", "sha256"), f"auslieferung[{i}]")
            pfad = _env_string(item.get("pfad"), f"auslieferung[{i}].pfad")
            if pfad.startswith("/") or ".." in pfad.split("/"):
                raise PruefungGescheitert(f"auslieferung[{i}].pfad: relativer Pfad ohne '..' erwartet")
            if pfad in gesehen:
                raise PruefungGescheitert(f"auslieferung: Pfad {pfad!r} doppelt")
            gesehen.add(pfad)
            h = _env_string(item.get("sha256"), f"auslieferung[{i}].sha256")
            if not _SHA256_RE.match(h):
                raise PruefungGescheitert(f"auslieferung[{i}].sha256: 64 Hex-Zeichen klein erwartet")
            auslieferung.append({"pfad": pfad, "sha256": h})
        auslieferung.sort(key=lambda r: r["pfad"])

    inputs_in = envelope.get("inputs")
    inputs: List[Dict[str, Any]] = []
    if inputs_in is not None:
        if not isinstance(inputs_in, list):
            raise PruefungGescheitert("inputs: Liste erwartet")
        for i, item in enumerate(inputs_in):
            if not isinstance(item, dict):
                raise PruefungGescheitert(f"inputs[{i}]: Objekt erwartet")
            _env_reject_unknown(item, _INPUT_FIELDS[version], f"inputs[{i}]")
            row: Dict[str, Any] = {
                "name": _env_string(item.get("name"), f"inputs[{i}].name"),
                "reference": _env_string(item.get("reference"), f"inputs[{i}].reference"),
            }
            if version != "1" and item.get("data_class") is not None:
                data_class = item["data_class"]
                if isinstance(data_class, bool) or data_class not in (1, 2, 3):
                    raise PruefungGescheitert(
                        f"inputs[{i}].data_class: nur die Klassen 1, 2, 3 sind definiert"
                    )
                row["data_class"] = data_class
            inputs.append(row)
        inputs.sort(key=lambda r: (r["name"], r["reference"], r.get("data_class", 0)))

    dataset_in = envelope.get("dataset")
    dataset: Optional[Dict[str, str]] = None
    if dataset_in is not None:
        if not isinstance(dataset_in, dict):
            raise PruefungGescheitert("dataset: Objekt erwartet")
        _env_reject_unknown(dataset_in, _DATASET_FIELDS, "dataset")
        dataset = {"id": _env_string(dataset_in.get("id"), "dataset.id")}
        _env_optional(dataset, dataset_in, "reference", "dataset")
        if dataset_in.get("manifest_digest") is not None:
            dataset["manifest_digest"] = _env_digest(
                dataset_in["manifest_digest"], "dataset.manifest_digest"
            )

    docs_in = envelope.get("source_documents")
    source_documents: List[Dict[str, str]] = []
    if docs_in is not None:
        if not isinstance(docs_in, list):
            raise PruefungGescheitert("source_documents: Liste erwartet")
        for i, item in enumerate(docs_in):
            if not isinstance(item, dict):
                raise PruefungGescheitert(f"source_documents[{i}]: Objekt erwartet")
            _env_reject_unknown(item, _SOURCE_DOCUMENT_FIELDS, f"source_documents[{i}]")
            doc_sha = _env_string(item.get("sha256"), f"source_documents[{i}].sha256")
            if not _SHA256_RE.match(doc_sha):
                raise PruefungGescheitert(
                    f"source_documents[{i}].sha256: 64 Hex-Zeichen in Kleinbuchstaben erwartet"
                )
            retrieved_at = item.get("retrieved_at")
            if not (isinstance(retrieved_at, str) and _TS_Z_RE.match(retrieved_at)):
                raise PruefungGescheitert(
                    f"source_documents[{i}].retrieved_at: nur das Format YYYY-MM-DDThh:mm:ssZ ist gueltig"
                )
            doc = {"sha256": doc_sha, "retrieved_at": retrieved_at}
            _env_optional(doc, item, "reference", f"source_documents[{i}]")
            source_documents.append(doc)
        source_documents.sort(
            key=lambda r: (r["sha256"], r["retrieved_at"], r.get("reference", ""))
        )

    as_of_in = envelope.get("as_of")
    as_of: Optional[Dict[str, Any]] = None
    if as_of_in is not None:
        if not isinstance(as_of_in, dict):
            raise PruefungGescheitert("as_of: Objekt erwartet")
        _env_reject_unknown(as_of_in, _AS_OF_FIELDS, "as_of")
        ts = as_of_in.get("timestamp")
        if not (isinstance(ts, str) and _TS_Z_RE.match(ts)):
            raise PruefungGescheitert("as_of.timestamp: nur das Format YYYY-MM-DDThh:mm:ssZ ist gueltig")
        as_of = {"timestamp": ts}
        positions = as_of_in.get("positions_without_knowledge_time")
        if positions is not None:
            if isinstance(positions, bool) or not isinstance(positions, int) or positions < 0:
                raise PruefungGescheitert(
                    "as_of.positions_without_knowledge_time: Ganzzahl >= 0 erwartet"
                )
            as_of["positions_without_knowledge_time"] = positions

    origin_in = envelope.get("origin")
    if not isinstance(origin_in, dict):
        raise PruefungGescheitert("origin: Objekt erwartet")
    _env_reject_unknown(origin_in, _ORIGIN_FIELDS, "origin")
    origin: Dict[str, Any] = {"kind": _env_string(origin_in.get("kind"), "origin.kind")}
    _env_optional(origin, origin_in, "description", "origin")

    out: Dict[str, Any] = {
        "envelope_version": version,
        "subject": subject,
        "created_at": created_at,
        "payload": payload,
        "method": method,
    }
    if auftrag is not None:
        out["auftrag"] = auftrag
    # is not None, nicht Wahrheitswert: der Erzeuger (envelope.py) behaelt
    # "auslieferung": [] im Umschlag, wenn eine leere Liste uebergeben wurde.
    # Mit "if auslieferung:" liesse der Verifier das Feld weg, rechnete einen
    # anderen envelope_hash und Schritt 1 schluege an einem einwandfreien Paket
    # fehl. Genau die Divergenzklasse, vor der der DECISIONS-Eintrag dieses PRs
    # warnt. Bei "auftrag" ist es eine Zeile darueber schon symmetrisch.
    if auslieferung_in is not None:
        out["auslieferung"] = auslieferung
    if inputs:
        out["inputs"] = inputs
    if dataset is not None:
        out["dataset"] = dataset
    if source_documents:
        out["source_documents"] = source_documents
    if as_of is not None:
        out["as_of"] = as_of
    out["origin"] = origin
    return json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def envelope_sha256(envelope: Any) -> str:
    return hashlib.sha256(canonical_envelope_bytes(envelope)).hexdigest()


# ===========================================================================
# Teil 2: Siegel v1 (signierte Serialisierung, seal_hash, Ed25519-Signatur,
# Merkle-Baum; Referenz: docs/SIEGEL_VERSIEGELUNG.md). Zweitimplementierung,
# kein Import.
# ===========================================================================

_SIGNED_FIELDS = (
    "seal_version",
    "sig_algo",
    "hash_algo",
    "key_id",
    "envelope_version",
    "envelope_hash",
    "leaf_index",
    "prev_root_hash",
    "sealed_at",
)


def seal_signed_bytes(record: Any) -> bytes:
    """Signierte Serialisierung v1: die neun Felder zeilenweise als name:wert."""
    if not isinstance(record, dict):
        raise PruefungGescheitert("seal: Objekt erwartet")
    if record.get("seal_version") != SEAL_VERSION:
        raise PruefungGescheitert(f"seal_version: nur {SEAL_VERSION!r} wird von diesem Verifier getragen")
    if record.get("sig_algo") != SEAL_SIG_ALGO:
        raise PruefungGescheitert(f"sig_algo: nur {SEAL_SIG_ALGO!r} wird von diesem Verifier getragen")
    if record.get("hash_algo") != SEAL_HASH_ALGO:
        raise PruefungGescheitert(f"hash_algo: nur {SEAL_HASH_ALGO!r} wird von diesem Verifier getragen")
    values: Dict[str, str] = {}
    for name in _SIGNED_FIELDS:
        v = record.get(name)
        if not isinstance(v, str) or v == "":
            raise PruefungGescheitert(f"{name}: nicht-leerer String erwartet")
        if "\n" in v:
            raise PruefungGescheitert(f"{name}: Zeilenumbruch ist nicht zulaessig")
        values[name] = v
    for name in ("envelope_hash", "prev_root_hash"):
        if not _SHA256_RE.match(values[name]):
            raise PruefungGescheitert(f"{name}: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    if not _LEAF_INDEX_RE.match(values["leaf_index"]):
        raise PruefungGescheitert("leaf_index: Dezimalzahl ohne fuehrende Nullen erwartet")
    if not _TS_Z_RE.match(values["sealed_at"]):
        raise PruefungGescheitert("sealed_at: nur das Format YYYY-MM-DDThh:mm:ssZ ist gueltig")
    return "\n".join(f"{name}:{values[name]}" for name in _SIGNED_FIELDS).encode("utf-8")


def recompute_seal_hash(record: Any) -> str:
    """
    seal_hash aus signierten Bytes + Signatur NEU gerechnet: dem Feld
    seal_hash im Record wird nirgends geglaubt. Der Hash bindet Inhalt UND
    Signatur, ein neu signierter Record aendert also seinen seal_hash.
    """
    message = seal_signed_bytes(record)
    signature = record.get("signature")
    if not isinstance(signature, str) or not _ED25519_SIG_RE.match(signature):
        raise PruefungGescheitert("signature: fehlt oder hat kein Ed25519-Hex-Format (128 Hex-Zeichen)")
    return hashlib.sha256(message + b"\n" + signature.encode("ascii")).hexdigest()


# --------------------------------------------------------- Ed25519 (RFC 8032)
# Eigene Pruef-Implementierung (nur verify, signieren kann und soll dieses
# Werkzeug nicht). Kurve und Ablauf: RFC 8032, 5.1; Punktarithmetik in
# erweiterten homogenen Koordinaten.

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P


def _ed_recover_x(y: int, sign_bit: int) -> int:
    if y >= _ED_P:
        raise PruefungGescheitert("ed25519: y-Koordinate ausserhalb des Feldes")
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        if sign_bit:
            raise PruefungGescheitert("ed25519: ungueltige Punkt-Kodierung")
        return 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        raise PruefungGescheitert("ed25519: Punkt liegt nicht auf der Kurve")
    if x & 1 != sign_bit:
        x = _ED_P - x
    return x


def _ed_decompress(data: bytes):
    if len(data) != 32:
        raise PruefungGescheitert("ed25519: Punkt-Kodierung hat nicht 32 Byte")
    y = int.from_bytes(data, "little")
    sign_bit = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign_bit)
    return (x, y, 1, x * y % _ED_P)


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


_ED_B = _ed_decompress(int.to_bytes((4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P, 32, "little"))


def _ed_equal(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032, 5.1.7. Liefert True/False; wirft nur bei falschen Laengen."""
    if len(public_key) != 32:
        raise PruefungGescheitert("ed25519: oeffentlicher Schluessel hat nicht 32 Byte")
    if len(signature) != 64:
        raise PruefungGescheitert("ed25519: Signatur hat nicht 64 Byte")
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    try:
        a_point = _ed_decompress(public_key)
        r_point = _ed_decompress(signature[:32])
    except PruefungGescheitert:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED_L
    return _ed_equal(_ed_mul(s, _ED_B), _ed_add(r_point, _ed_mul(k, a_point)))


def verify_seal_signature(record: Dict[str, Any], public_key_hex: str) -> None:
    """Ed25519-Signatur des Siegels gegen den oeffentlichen Schluessel."""
    if not isinstance(public_key_hex, str) or not re.match(r"^[0-9a-fA-F]{64}$", public_key_hex):
        raise PruefungGescheitert("public_key: 32 Byte Hex erwartet")
    message = seal_signed_bytes(record)
    signature = record.get("signature")
    if not isinstance(signature, str) or not _ED25519_SIG_RE.match(signature):
        raise PruefungGescheitert("signature: fehlt oder hat kein Ed25519-Hex-Format (128 Hex-Zeichen)")
    if not ed25519_verify(bytes.fromhex(public_key_hex), message, bytes.fromhex(signature)):
        raise PruefungGescheitert(
            "signature: Ed25519 verifiziert nicht (Inhalt veraendert oder anderer Schluessel)"
        )


# ------------------------------------------------------ Merkle-Baum (RFC 6962)


def _mt_leaf_hash(seal_hash: str) -> bytes:
    if not isinstance(seal_hash, str) or not _SHA256_RE.match(seal_hash):
        raise PruefungGescheitert("seal_hash: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    return hashlib.sha256(b"\x00" + bytes.fromhex(seal_hash)).digest()


def _mt_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mt_root_raw(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _mt_node_hash(_mt_root_raw(leaves[:k]), _mt_root_raw(leaves[k:]))


def merkle_tree_root(seal_hashes: Sequence[str]) -> str:
    """Wurzel (Hex) ueber die seal_hashes in Blatt-Reihenfolge (RFC 6962 MTH)."""
    return _mt_root_raw([_mt_leaf_hash(h) for h in seal_hashes]).hex()


def verify_merkle_membership(
    seal_hash: str, leaf_index: int, tree_size: int, audit_path: Sequence[str], root_hash: str
) -> None:
    """
    Fuehrt das Blatt ueber den Pfad zur Wurzel (RFC 6962/9162, iterative
    Fassung) und vergleicht mit root_hash. Wirft PruefungGescheitert.
    """
    if not (0 <= leaf_index < tree_size):
        raise PruefungGescheitert(f"leaf_index: {leaf_index} liegt nicht in [0, {tree_size})")
    node = _mt_leaf_hash(seal_hash)
    fn, sn = leaf_index, tree_size - 1
    for sibling_hex in audit_path:
        if not isinstance(sibling_hex, str) or not _SHA256_RE.match(sibling_hex):
            raise PruefungGescheitert("audit_path: 64 Hex-Zeichen je Knoten erwartet")
        sibling = bytes.fromhex(sibling_hex)
        if sn == 0:
            raise PruefungGescheitert("audit_path: laenger als der Pfad zur Wurzel")
        if fn == sn or fn % 2 == 1:
            node = _mt_node_hash(sibling, node)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = _mt_node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise PruefungGescheitert("audit_path: zu kurz, erreicht die Wurzel nicht")
    if not isinstance(root_hash, str) or not _SHA256_RE.match(root_hash):
        raise PruefungGescheitert("root_hash: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    if node.hex() != root_hash:
        raise PruefungGescheitert(
            "der Zugehoerigkeitsnachweis fuehrt nicht zur angegebenen Wurzel "
            "(fremdes Blatt, falsche Position oder manipulierter Pfad)"
        )


# ===========================================================================
# Teil 3: DER lesen und schreiben (minimal, strikt; jede Abweichung ist ein
# lauter Fehler). Gebraucht fuer RFC 3161 / CMS / X.509.
# ===========================================================================

_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_UTF8_STRING = 0x0C
_TAG_GENERALIZED_TIME = 0x18
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_CONTEXT_0 = 0xA0
_TAG_CONTEXT_1 = 0xA1


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return _der(_TAG_OID, bytes(body))


def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise PruefungGescheitert("DER: unerwartetes Ende")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise PruefungGescheitert("DER: High-Tag-Number-Form wird nicht getragen")
    offset += 1
    if offset >= len(data):
        raise PruefungGescheitert("DER: Laengenfeld fehlt")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise PruefungGescheitert("DER: unplausibles Laengenfeld")
        if offset + n > len(data):
            raise PruefungGescheitert("DER: Laengenfeld abgeschnitten")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    if offset + length > len(data):
        raise PruefungGescheitert("DER: Inhalt abgeschnitten")
    return tag, data[offset:offset + length], offset + length


def _children(content: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, inner, offset = _read_tlv(content, offset)
        out.append((tag, inner))
    return out


def _expect(tag_got: int, tag_want: int, where: str) -> None:
    if tag_got != tag_want:
        raise PruefungGescheitert(
            f"DER: {where}: Tag 0x{tag_want:02x} erwartet, 0x{tag_got:02x} gelesen"
        )


def _decode_integer(content: bytes, where: str) -> int:
    if not content:
        raise PruefungGescheitert(f"DER: {where}: leerer INTEGER")
    return int.from_bytes(content, "big", signed=True)


def _decode_oid(content: bytes) -> str:
    if not content:
        raise PruefungGescheitert("DER: leerer OID")
    parts = [content[0] // 40, content[0] % 40]
    arc = 0
    for b in content[1:]:
        arc = (arc << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(arc)
            arc = 0
    return ".".join(str(p) for p in parts)


# ===========================================================================
# Teil 4: Kryptographie (nur Verifikation): RSA PKCS#1 v1.5 und ECDSA auf
# den NIST-Kurven P-256/P-384, Hashes SHA-256/384/512. Bewusst klein und
# strikt: unbekannte Verfahren sind ein lauter Fehler, kein Weiterraten.
# ===========================================================================

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SHA1 = "1.3.14.3.2.26"

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"

OID_CURVE_P256 = "1.2.840.10045.3.1.7"
OID_CURVE_P384 = "1.3.132.0.34"

_HASHES = {OID_SHA256: hashlib.sha256, OID_SHA384: hashlib.sha384, OID_SHA512: hashlib.sha512}

# Signaturalgorithmus -> (Verfahren, Hash-OID oder None = aus digestAlgorithm)
_SIG_ALGOS = {
    OID_RSA_ENCRYPTION: ("rsa", None),
    OID_SHA256_WITH_RSA: ("rsa", OID_SHA256),
    OID_SHA384_WITH_RSA: ("rsa", OID_SHA384),
    OID_SHA512_WITH_RSA: ("rsa", OID_SHA512),
    OID_ECDSA_SHA256: ("ecdsa", OID_SHA256),
    OID_ECDSA_SHA384: ("ecdsa", OID_SHA384),
    OID_ECDSA_SHA512: ("ecdsa", OID_SHA512),
}

# NIST-Kurven (FIPS 186-4). Die Primzahlen stehen als Formel da, damit kein
# Uebertragungsfehler in einer langen Hex-Konstante stecken kann; alle Werte
# sind gegen die Kurvengleichung und die Ordnung des Basispunkts geprueft
# (backend/tests/test_verifier.py).
_CURVES = {
    OID_CURVE_P256: {
        "p": 2**256 - 2**224 + 2**192 + 2**96 - 1,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        "size": 32,
    },
    OID_CURVE_P384: {
        "p": 2**384 - 2**128 - 2**96 + 2**32 - 1,
        "b": 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "gx": 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        "gy": 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        "size": 48,
    },
}


def _ec_add(P, Q, p: int, a: int):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def _ec_mul(k: int, P, p: int, a: int):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, p, a)
        P = _ec_add(P, P, p, a)
        k >>= 1
    return R


def _ecdsa_verify(curve_oid: str, point: Tuple[int, int], signature_der: bytes, digest: bytes) -> None:
    curve = _CURVES.get(curve_oid)
    if curve is None:
        raise PruefungGescheitert(f"ECDSA: Kurve {curve_oid} wird nicht getragen (nur P-256/P-384)")
    p, n = curve["p"], curve["n"]
    a = p - 3
    qx, qy = point
    if not (0 < qx < p and 0 < qy < p) or (qy * qy - (qx**3 + a * qx + curve["b"])) % p != 0:
        raise PruefungGescheitert("ECDSA: der oeffentliche Schluessel liegt nicht auf der Kurve")
    tag, sig, _ = _read_tlv(signature_der, 0)
    _expect(tag, _TAG_SEQUENCE, "ECDSA-Signatur")
    parts = _children(sig)
    if len(parts) != 2 or parts[0][0] != _TAG_INTEGER or parts[1][0] != _TAG_INTEGER:
        raise PruefungGescheitert("ECDSA-Signatur: SEQUENCE aus r und s erwartet")
    r = _decode_integer(parts[0][1], "r")
    s = _decode_integer(parts[1][1], "s")
    if not (1 <= r < n and 1 <= s < n):
        raise PruefungGescheitert("ECDSA-Signatur: r oder s ausserhalb des gueltigen Bereichs")
    e = int.from_bytes(digest, "big")
    extra_bits = len(digest) * 8 - n.bit_length()
    if extra_bits > 0:
        e >>= extra_bits
    w = pow(s, -1, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    G = (curve["gx"], curve["gy"])
    R = _ec_add(_ec_mul(u1, G, p, a), _ec_mul(u2, (qx, qy), p, a), p, a)
    if R is None or R[0] % n != r:
        raise PruefungGescheitert("ECDSA: Signatur verifiziert nicht")


def _rsa_pkcs1v15_verify(modulus: int, exponent: int, signature: bytes, digest: bytes, hash_oid: str) -> None:
    k = (modulus.bit_length() + 7) // 8
    if len(signature) != k:
        raise PruefungGescheitert("RSA: Signaturlaenge passt nicht zum Modulus")
    m = pow(int.from_bytes(signature, "big"), exponent, modulus)
    em = m.to_bytes(k, "big")
    # DigestInfo in beiden ueblichen Formen (mit und ohne NULL-Parameter).
    candidates = []
    for algo_params in (_der_oid(hash_oid) + _der(_TAG_NULL, b""), _der_oid(hash_oid)):
        digest_info = _der(_TAG_SEQUENCE, _der(_TAG_SEQUENCE, algo_params) + _der(_TAG_OCTET_STRING, digest))
        pad_len = k - len(digest_info) - 3
        if pad_len < 8:
            raise PruefungGescheitert("RSA: Modulus zu klein fuer den Digest")
        candidates.append(b"\x00\x01" + b"\xff" * pad_len + b"\x00" + digest_info)
    if not any(hmac.compare_digest(em, c) for c in candidates):
        raise PruefungGescheitert("RSA: Signatur verifiziert nicht")


# ===========================================================================
# Teil 5: X.509 (minimal): Serial, Issuer, SubjectPublicKeyInfo. Vollstaendige
# Zertifikatsketten- und Sperrlistenpruefung ist AUSSERHALB dieses Werkzeugs
# (Aufgabe der PKI-Werkzeuge des Pruefers, siehe docs/VERIFIKATION.md).
# ===========================================================================

def parse_certificate(cert_der: bytes) -> Dict[str, Any]:
    tag, cert, _ = _read_tlv(cert_der, 0)
    _expect(tag, _TAG_SEQUENCE, "Certificate")
    parts = _children(cert)
    if len(parts) != 3:
        raise PruefungGescheitert("Certificate: tbsCertificate, signatureAlgorithm, signature erwartet")
    _expect(parts[0][0], _TAG_SEQUENCE, "tbsCertificate")
    tbs = _children(parts[0][1])
    idx = 1 if tbs and tbs[0][0] == _TAG_CONTEXT_0 else 0
    if len(tbs) < idx + 6:
        raise PruefungGescheitert("tbsCertificate: zu wenige Felder")
    _expect(tbs[idx][0], _TAG_INTEGER, "serialNumber")
    serial = _decode_integer(tbs[idx][1], "serialNumber")
    _expect(tbs[idx + 2][0], _TAG_SEQUENCE, "issuer")
    issuer_der = _der(_TAG_SEQUENCE, tbs[idx + 2][1])
    _expect(tbs[idx + 5][0], _TAG_SEQUENCE, "subjectPublicKeyInfo")
    spki = _children(tbs[idx + 5][1])
    if len(spki) != 2 or spki[0][0] != _TAG_SEQUENCE or spki[1][0] != _TAG_BIT_STRING:
        raise PruefungGescheitert("subjectPublicKeyInfo: AlgorithmIdentifier + BIT STRING erwartet")
    algo_parts = _children(spki[0][1])
    if not algo_parts or algo_parts[0][0] != _TAG_OID:
        raise PruefungGescheitert("subjectPublicKeyInfo: Algorithmus-OID erwartet")
    key_algo = _decode_oid(algo_parts[0][1])
    bit_string = spki[1][1]
    if not bit_string or bit_string[0] != 0x00:
        raise PruefungGescheitert("subjectPublicKeyInfo: BIT STRING mit 0 ungenutzten Bits erwartet")
    key_bytes = bit_string[1:]

    out: Dict[str, Any] = {
        "der": cert_der,
        "serial": serial,
        "issuer_der": issuer_der,
        "key_algo": key_algo,
        "sha1": hashlib.sha1(cert_der).hexdigest(),
        "sha256": hashlib.sha256(cert_der).hexdigest(),
    }
    if key_algo == OID_RSA_ENCRYPTION:
        tag, rsa_key, _ = _read_tlv(key_bytes, 0)
        _expect(tag, _TAG_SEQUENCE, "RSAPublicKey")
        ints = _children(rsa_key)
        if len(ints) != 2:
            raise PruefungGescheitert("RSAPublicKey: Modulus und Exponent erwartet")
        out["rsa_n"] = _decode_integer(ints[0][1], "modulus")
        out["rsa_e"] = _decode_integer(ints[1][1], "exponent")
    elif key_algo == OID_EC_PUBLIC_KEY:
        if len(algo_parts) < 2 or algo_parts[1][0] != _TAG_OID:
            raise PruefungGescheitert("EC-Schluessel: benannte Kurve (OID) erwartet")
        curve_oid = _decode_oid(algo_parts[1][1])
        curve = _CURVES.get(curve_oid)
        if curve is None:
            raise PruefungGescheitert(f"EC-Schluessel: Kurve {curve_oid} wird nicht getragen")
        size = curve["size"]
        if len(key_bytes) != 1 + 2 * size or key_bytes[0] != 0x04:
            raise PruefungGescheitert("EC-Schluessel: unkomprimierter Punkt (0x04) erwartet")
        out["ec_curve"] = curve_oid
        out["ec_point"] = (
            int.from_bytes(key_bytes[1:1 + size], "big"),
            int.from_bytes(key_bytes[1 + size:], "big"),
        )
    else:
        raise PruefungGescheitert(f"Zertifikat: Schluesselverfahren {key_algo} wird nicht getragen")
    return out


def load_certificate_file(path: str) -> bytes:
    """Liest ein Zertifikat als DER oder PEM (erster CERTIFICATE-Block)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        text = raw.decode("ascii", errors="strict")
        m = re.search(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.DOTALL
        )
        if not m:
            raise PaketFehler(f"{path}: PEM-Zertifikatsblock unvollstaendig")
        return base64.b64decode("".join(m.group(1).split()))
    return raw


# ===========================================================================
# Teil 6: RFC-3161-Token (CMS SignedData -> TSTInfo) einlesen und die
# TSA-Signatur vollstaendig pruefen.
# ===========================================================================

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ATTR_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"


def _parse_tst_info(tst_der: bytes) -> Dict[str, Any]:
    tag, tst, _ = _read_tlv(tst_der, 0)
    _expect(tag, _TAG_SEQUENCE, "TSTInfo")
    fields = _children(tst)
    if len(fields) < 5:
        raise PruefungGescheitert("TSTInfo: version, policy, messageImprint, serialNumber, genTime erwartet")
    version = _decode_integer(fields[0][1], "TSTInfo.version")
    if version != 1:
        raise PruefungGescheitert(f"TSTInfo.version: 1 erwartet, {version} gelesen")
    imprint_parts = _children(fields[2][1])
    if len(imprint_parts) != 2:
        raise PruefungGescheitert("messageImprint: hashAlgorithm + hashedMessage erwartet")
    algo_parts = _children(imprint_parts[0][1])
    if not algo_parts or algo_parts[0][0] != _TAG_OID:
        raise PruefungGescheitert("messageImprint.hashAlgorithm: OID erwartet")
    _expect(fields[4][0], _TAG_GENERALIZED_TIME, "TSTInfo.genTime")
    gen_raw = fields[4][1].decode("ascii", errors="strict")
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$", gen_raw)
    if not m:
        raise PruefungGescheitert(f"genTime: {gen_raw!r} ist nicht das erwartete UTC-Format")
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    return {
        "hash_algo_oid": _decode_oid(algo_parts[0][1]),
        "hashed_message": imprint_parts[1][1].hex(),
        "serial": _decode_integer(fields[3][1], "TSTInfo.serialNumber"),
        "gen_time": f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}Z",
    }


def _attr_values(attrs_content: bytes) -> Dict[str, List[bytes]]:
    """signedAttrs-Inhalt -> {OID: [Werte-DER der SET-Elemente]}."""
    out: Dict[str, List[bytes]] = {}
    for tag, attr in _children(attrs_content):
        _expect(tag, _TAG_SEQUENCE, "Attribute")
        parts = _children(attr)
        if len(parts) != 2 or parts[0][0] != _TAG_OID or parts[1][0] != _TAG_SET:
            raise PruefungGescheitert("Attribute: OID + SET erwartet")
        oid = _decode_oid(parts[0][1])
        out.setdefault(oid, [])
        offset = 0
        content = parts[1][1]
        while offset < len(content):
            start = offset
            _, _, offset = _read_tlv(content, offset)
            out[oid].append(content[start:offset])
    return out


def verify_timestamp_token(token_der: bytes, trusted_cert_der: Optional[Any] = None) -> Dict[str, Any]:
    """
    Prueft ein RFC-3161-Token vollstaendig gegen sich selbst: TSTInfo,
    messageDigest- und contentType-Attribut, ESSCertID (wenn vorhanden) und
    die TSA-Signatur ueber den signierten Attributen mit dem Schluessel aus
    dem im Token mitgefuehrten Signer-Zertifikat. Mit trusted_cert_der
    (ein Zertifikat oder eine Liste - beim Doppel-Anker legt der Pruefer je
    Dienst eines vor) wird das Signer-Zertifikat zusaetzlich byte-genau
    gegen die vorgelegten Vertrauenszertifikate gehalten (Treffer = eines
    passt). Liefert Token-Infos fuer die Ausgabe.

    Grenze: die Kette VOM Signer-Zertifikat zu einer Wurzel und der
    Sperrstatus werden hier nicht geprueft (docs/VERIFIKATION.md nennt die
    openssl-Kommandos dafuer).
    """
    tag, content_info, _ = _read_tlv(token_der, 0)
    _expect(tag, _TAG_SEQUENCE, "TimeStampToken/ContentInfo")
    ci = _children(content_info)
    if len(ci) != 2 or ci[0][0] != _TAG_OID:
        raise PruefungGescheitert("ContentInfo: contentType + content erwartet")
    if _decode_oid(ci[0][1]) != OID_SIGNED_DATA:
        raise PruefungGescheitert("ContentInfo: contentType ist nicht CMS signedData")
    _expect(ci[1][0], _TAG_CONTEXT_0, "ContentInfo.content")
    tag, signed_data, _ = _read_tlv(ci[1][1], 0)
    _expect(tag, _TAG_SEQUENCE, "SignedData")
    sd = _children(signed_data)
    if len(sd) < 4:
        raise PruefungGescheitert("SignedData: version, digestAlgorithms, encapContentInfo, signerInfos erwartet")

    # EncapsulatedContentInfo -> TSTInfo-Bytes
    _expect(sd[2][0], _TAG_SEQUENCE, "EncapsulatedContentInfo")
    eci = _children(sd[2][1])
    if len(eci) < 2 or eci[0][0] != _TAG_OID or _decode_oid(eci[0][1]) != OID_TST_INFO:
        raise PruefungGescheitert("EncapsulatedContentInfo: eContentType id-ct-TSTInfo erwartet")
    _expect(eci[1][0], _TAG_CONTEXT_0, "eContent")
    tag, tst_octets, _ = _read_tlv(eci[1][1], 0)
    _expect(tag, _TAG_OCTET_STRING, "eContent OCTET STRING")
    info = _parse_tst_info(tst_octets)

    # Zertifikate [0] und SignerInfos (SET) einsammeln
    certificates: List[Dict[str, Any]] = []
    signer_infos_raw: Optional[bytes] = None
    for tag_f, content_f in sd[3:]:
        if tag_f == _TAG_CONTEXT_0:
            offset = 0
            while offset < len(content_f):
                start = offset
                cert_tag, _, offset = _read_tlv(content_f, offset)
                if cert_tag == _TAG_SEQUENCE:
                    certificates.append(parse_certificate(content_f[start:offset]))
        elif tag_f == _TAG_SET:
            signer_infos_raw = content_f
    if signer_infos_raw is None:
        raise PruefungGescheitert("SignedData: signerInfos fehlen")
    if not certificates:
        raise PruefungGescheitert(
            "SignedData: kein Zertifikat im Token (die TSA haette es mitfuehren muessen, certReq)"
        )
    signer_infos = _children(signer_infos_raw)
    if len(signer_infos) != 1:
        raise PruefungGescheitert(f"signerInfos: genau ein Signer erwartet, {len(signer_infos)} gelesen")
    _expect(signer_infos[0][0], _TAG_SEQUENCE, "SignerInfo")
    si = _children(signer_infos[0][1])
    if len(si) < 5:
        raise PruefungGescheitert("SignerInfo: zu wenige Felder")

    # sid: IssuerAndSerialNumber -> Signer-Zertifikat unter den mitgefuehrten finden
    _expect(si[1][0], _TAG_SEQUENCE, "SignerInfo.sid (IssuerAndSerialNumber erwartet)")
    sid = _children(si[1][1])
    if len(sid) != 2 or sid[0][0] != _TAG_SEQUENCE or sid[1][0] != _TAG_INTEGER:
        raise PruefungGescheitert("IssuerAndSerialNumber: Name + Serial erwartet")
    sid_issuer_der = _der(_TAG_SEQUENCE, sid[0][1])
    sid_serial = _decode_integer(sid[1][1], "sid.serial")
    signer_cert = None
    for cert in certificates:
        if cert["serial"] == sid_serial and cert["issuer_der"] == sid_issuer_der:
            signer_cert = cert
            break
    if signer_cert is None:
        raise PruefungGescheitert("SignerInfo: das benannte Signer-Zertifikat ist nicht im Token enthalten")

    # digestAlgorithm, signedAttrs, signatureAlgorithm, signature
    _expect(si[2][0], _TAG_SEQUENCE, "SignerInfo.digestAlgorithm")
    digest_parts = _children(si[2][1])
    if not digest_parts or digest_parts[0][0] != _TAG_OID:
        raise PruefungGescheitert("digestAlgorithm: OID erwartet")
    digest_oid = _decode_oid(digest_parts[0][1])
    if digest_oid not in _HASHES:
        raise PruefungGescheitert(f"digestAlgorithm: {digest_oid} wird nicht getragen (nur SHA-256/384/512)")
    if si[3][0] != _TAG_CONTEXT_0:
        raise PruefungGescheitert(
            "SignerInfo: signedAttrs fehlen (RFC 3161 verlangt sie fuer Zeitstempel-Token)"
        )
    signed_attrs_content = si[3][1]
    _expect(si[4][0], _TAG_SEQUENCE, "SignerInfo.signatureAlgorithm")
    sig_algo_parts = _children(si[4][1])
    if not sig_algo_parts or sig_algo_parts[0][0] != _TAG_OID:
        raise PruefungGescheitert("signatureAlgorithm: OID erwartet")
    sig_algo_oid = _decode_oid(sig_algo_parts[0][1])
    if sig_algo_oid not in _SIG_ALGOS:
        raise PruefungGescheitert(f"signatureAlgorithm: {sig_algo_oid} wird nicht getragen")
    scheme, sig_hash_oid = _SIG_ALGOS[sig_algo_oid]
    if sig_hash_oid is None:
        sig_hash_oid = digest_oid
    if len(si) < 6 or si[5][0] != _TAG_OCTET_STRING:
        raise PruefungGescheitert("SignerInfo: signature (OCTET STRING) erwartet")
    signature = si[5][1]

    # Signierte Attribute: messageDigest muss der Hash der TSTInfo-Bytes sein,
    # contentType muss id-ct-TSTInfo benennen (sonst liesse sich der Inhalt
    # gegen einen anderen CMS-Typ austauschen).
    attrs = _attr_values(signed_attrs_content)
    md_values = attrs.get(OID_ATTR_MESSAGE_DIGEST, [])
    if len(md_values) != 1:
        raise PruefungGescheitert("signedAttrs: genau ein messageDigest-Attribut erwartet")
    tag, md_octets, _ = _read_tlv(md_values[0], 0)
    _expect(tag, _TAG_OCTET_STRING, "messageDigest")
    expected_md = _HASHES[digest_oid](tst_octets).digest()
    if not hmac.compare_digest(md_octets, expected_md):
        raise PruefungGescheitert(
            "messageDigest: der signierte Digest passt nicht zum TSTInfo-Inhalt (Token manipuliert)"
        )
    ct_values = attrs.get(OID_ATTR_CONTENT_TYPE, [])
    if len(ct_values) != 1:
        raise PruefungGescheitert("signedAttrs: genau ein contentType-Attribut erwartet")
    tag, ct_oid, _ = _read_tlv(ct_values[0], 0)
    if tag != _TAG_OID or _decode_oid(ct_oid) != OID_TST_INFO:
        raise PruefungGescheitert("contentType-Attribut: id-ct-TSTInfo erwartet")

    # ESSCertID (signingCertificate v1/v2), wenn vorhanden: bindet die
    # Signatur an genau dieses Zertifikat.
    ess_checked = False
    for attr_oid, hash_fn, default_size in (
        (OID_ATTR_SIGNING_CERT, hashlib.sha1, 20),
        (OID_ATTR_SIGNING_CERT_V2, hashlib.sha256, 32),
    ):
        for value in attrs.get(attr_oid, []):
            tag, sc, _ = _read_tlv(value, 0)
            _expect(tag, _TAG_SEQUENCE, "signingCertificate")
            sc_parts = _children(sc)
            if not sc_parts or sc_parts[0][0] != _TAG_SEQUENCE:
                raise PruefungGescheitert("signingCertificate: certs-Liste erwartet")
            cert_ids = _children(sc_parts[0][1])
            if not cert_ids or cert_ids[0][0] != _TAG_SEQUENCE:
                raise PruefungGescheitert("signingCertificate: ESSCertID erwartet")
            id_parts = _children(cert_ids[0][1])
            # v2 darf mit einem AlgorithmIdentifier beginnen; der Hash selbst
            # ist das erste OCTET STRING.
            cert_hash = None
            for tag_i, content_i in id_parts:
                if tag_i == _TAG_OCTET_STRING:
                    cert_hash = content_i
                    break
            if cert_hash is None or len(cert_hash) != default_size:
                raise PruefungGescheitert("ESSCertID: Zertifikats-Hash fehlt oder hat die falsche Laenge")
            if not hmac.compare_digest(cert_hash, hash_fn(signer_cert["der"]).digest()):
                raise PruefungGescheitert(
                    "ESSCertID: der signierte Zertifikats-Hash passt nicht zum Signer-Zertifikat"
                )
            ess_checked = True

    # Die eigentliche Signatur: ueber der DER-Form der signedAttrs als SET
    # (RFC 5652, 5.4: das implizite [0]-Tag wird fuer die Signatur durch das
    # explizite SET-Tag ersetzt).
    signed_attrs_der = _der(_TAG_SET, signed_attrs_content)
    digest_for_sig = _HASHES[sig_hash_oid](signed_attrs_der).digest()
    if scheme == "rsa":
        if signer_cert["key_algo"] != OID_RSA_ENCRYPTION:
            raise PruefungGescheitert("Signatur: RSA-Signatur, aber das Zertifikat traegt keinen RSA-Schluessel")
        _rsa_pkcs1v15_verify(signer_cert["rsa_n"], signer_cert["rsa_e"], signature, digest_for_sig, sig_hash_oid)
    else:
        if signer_cert["key_algo"] != OID_EC_PUBLIC_KEY:
            raise PruefungGescheitert("Signatur: ECDSA-Signatur, aber das Zertifikat traegt keinen EC-Schluessel")
        _ecdsa_verify(signer_cert["ec_curve"], signer_cert["ec_point"], signature, digest_for_sig)

    trusted_match = None
    if trusted_cert_der is not None:
        certs = trusted_cert_der if isinstance(trusted_cert_der, (list, tuple)) else [trusted_cert_der]
        trusted_match = any(bytes(c) == bytes(signer_cert["der"]) for c in certs)

    info.update(
        {
            "signature_scheme": scheme,
            "signature_algo_oid": sig_algo_oid,
            "digest_oid": digest_oid,
            "ess_cert_id_checked": ess_checked,
            "signer_cert_sha256": signer_cert["sha256"],
            "signer_cert_serial": signer_cert["serial"],
            "certificates_in_token": len(certificates),
            "trusted_cert_match": trusted_match,
        }
    )
    return info


# ===========================================================================
# Teil 7: Paket laden und die fuenf Pruefschritte fahren.
# ===========================================================================

# Schwelle fuer den Abstand zwischen behauptetem Siegeldatum und bewiesener
# Zeit (S6/A6, #116). Bewusst grosszuegig: der Nachhol-Pfad aus S3 verankert
# legitim spaeter, ein Abstand ist also kein Fehler. Darueber wird er zum
# sichtbaren BEFUND, nicht zum Fehlschlag.
SCHWELLE_ANKER_ABSTAND_STUNDEN = 72

# Die Gegenrichtung (S6-F2, #148): sealed_at NACH gen_time. Das Token bezeugt
# einen Hash, der das sealed_at bereits enthaelt - das Siegel muss also vor dem
# Token existiert haben. Ein echter Vorlauf ist damit unmoeglich und ein
# FEHLSCHLAG, nicht ein Befund: es gibt keinen legitimen Nachhol-Pfad in diese
# Richtung.
#
# Die Toleranz deckt genau einen Fall ab, der nichts mit Faelschung zu tun hat:
# die Uhr des Erzeugers geht gegenueber der Uhr der Zeitstempelstelle vor. Der
# Erzeuger siegelt und holt das Token unmittelbar danach ueber das Netz; bei
# Sekundenabweichung der beiden Uhren stuende sonst eine ehrliche Akte rot da.
# Bewusst klein gehalten - ein Vorlauf nuetzt einem Faelscher nichts, gefaehrlich
# ist die Rueckdatierung, und die faengt SCHWELLE_ANKER_ABSTAND_STUNDEN.
TOLERANZ_UHRENVORLAUF_SEKUNDEN = 60


def _zeitabstand_stunden(behauptet: str, bewiesen: str) -> Optional[float]:
    """Stunden, die die BEHAUPTUNG vor dem Beweis liegt; None wenn unlesbar."""
    def _lies(t: str) -> Optional[float]:
        t = t.strip().replace("Z", "+0000")
        for form in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
            try:
                return datetime.datetime.strptime(t, form).timestamp()
            except ValueError:
                continue
        return None
    a, b = _lies(behauptet), _lies(bewiesen)
    if a is None or b is None:
        return None
    return (b - a) / 3600.0


def _zeit_gegen_anker(behauptet: Optional[str], bewiesen: str, was: str) -> Tuple[
        Optional[str], Optional[str]]:
    """created_at gegen genTime, in BEIDE Richtungen (Z2-F1, #145).

    Liefert (Fehlschlag, Befund); hoechstens eines ist gesetzt.

    Dieselbe Haertung wie im Siegel-Pfad fuer ``sealed_at`` (S6/A6 #116,
    S6-F2 #148), hier auf die Zeitangaben des Verzeichnisses uebertragen -
    erfunden wird nichts, die Schwellen sind dieselben Konstanten.

    Was das Token leistet und was nicht: es bezeugt, dass ein HASH zu einem
    Zeitpunkt existierte. Es bezeugt nicht, dass der Datensatz daneben zu dem
    Zeitpunkt entstand, den er selbst behauptet. Ohne diesen Vergleich besteht
    ein heute gebauter Stand mit ``created_at`` von 2020 die Pruefung
    anstandslos, und der Bericht sagt dazu "ein Zeitpunkt, den nicht wir
    bezeugen" - der Leser denkt an 2020, bezeugt ist heute.

    Zwei Richtungen, zwei Antworten:

    - Behauptung deutlich VOR der bezeugten Zeit: der legitime Nachhol-Fall
      (S3, Anker spaeter). BEFUND, kein Fehlschlag - sonst faellt jeder
      ehrliche Bestand, dessen Anker einen Tag spaeter kam.
    - Behauptung NACH der bezeugten Zeit: die Wurzel war bezeugt, bevor der
      Stand entstanden sein will, der sie bildet. Ein legitimer Weg dorthin
      existiert nicht, das ist ein FEHLSCHLAG.

    Die Grenze dieser zweiten Richtung, ausdruecklich: im Siegel-Pfad ist sie
    kryptografisch zwingend, weil der bezeugte Hash das ``sealed_at`` selbst
    enthaelt. Hier enthaelt der bezeugte Hash die Zeitangabe NICHT - die Wurzel
    steht ueber den Zeilen, nicht ueber dem Kopf. Zwingend ist die Richtung
    hier durch den Ablauf: die Wurzel entsteht beim Bilden des Standes, ein
    Token darauf kann es vorher nicht geben. Wer den Ablauf umgeht, faellt
    hier auf - wer ihn faelscht, muesste die Signatur des Standes brechen.
    """
    if not behauptet:
        return None, None
    abstand = _zeitabstand_stunden(behauptet, bewiesen)
    if abstand is None:
        return None, f"{was} {behauptet}: Abstand zur bezeugten Zeit nicht berechenbar"
    if abstand < -(TOLERANZ_UHRENVORLAUF_SEKUNDEN / 3600.0):
        return (
            f"{was} {behauptet} liegt {-abstand:.0f} h NACH der bezeugten Zeit {bewiesen}. "
            "Die Wurzel war damit bezeugt, bevor der Stand entstanden sein will, der sie "
            "bildet; einen legitimen Weg dorthin gibt es nicht (Uhrenvorlauf bis "
            f"{TOLERANZ_UHRENVORLAUF_SEKUNDEN} s toleriert)"
        ), None
    if abstand > SCHWELLE_ANKER_ABSTAND_STUNDEN:
        return None, (
            f"{was} {behauptet} liegt {abstand:.0f} h vor der bezeugten Zeit {bewiesen} "
            f"(Schwelle {SCHWELLE_ANKER_ABSTAND_STUNDEN} h). Das Token bezeugt den frueheren "
            "Zeitpunkt NICHT; wer ihn braucht, braucht einen Anker von damals"
        )
    return None, None


def _gekuerzt(eintraege: Sequence[str], zeige: int = 4) -> str:
    """Aufzaehlung mit Nennung dessen, was NICHT dasteht.

    Die uebrigen Listen im Bericht schneiden bei [:8] ab, ohne es zu sagen -
    wer fuenf Befunde hat und vier liest, haelt vier fuer alle. Hier wird die
    Zahl genannt; das ist billiger als jede Erklaerung hinterher.
    """
    sichtbar = "; ".join(eintraege[:zeige])
    rest = len(eintraege) - zeige
    return sichtbar if rest <= 0 else f"{sichtbar}; und {rest} weitere(r) desselben Befunds"


def _check(name: str, status: str, detail: str) -> Dict[str, str]:
    return {"pruefung": name, "ergebnis": status, "begruendung": detail}


def load_package(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            package = json.load(fh)
    except OSError as e:
        raise PaketFehler(f"Paket nicht lesbar: {e}")
    except ValueError as e:
        raise PaketFehler(f"Paket ist kein gueltiges JSON: {e}")
    if not isinstance(package, dict):
        raise PaketFehler("Paket: JSON-Objekt erwartet")
    if package.get("package_type") != PACKAGE_TYPE:
        raise PaketFehler(f"Paket: package_type {PACKAGE_TYPE!r} erwartet")
    if package.get("package_version") != PACKAGE_VERSION:
        raise PaketFehler(f"Paket: package_version {PACKAGE_VERSION!r} erwartet")
    if not isinstance(package.get("seal"), dict):
        raise PaketFehler("Paket: seal-Objekt fehlt")
    _inhaltsdatei_lesen(package, os.path.dirname(path))
    return package


def inhaltsdatei_name(envelope: Any) -> Optional[str]:
    """Der Dateiname, unter dem der Umschlag die Nutzlast fuehrt.

    Genommen wird das letzte Glied von payload.reference
    ("werk://kriterienwerk-v0.4/KRITERIENWERK.md" -> "KRITERIENWERK.md",
    "phm://belegakte/.../akte.json" -> "akte.json"). Der Name steht im
    versiegelten Umschlag; ein Faelscher kann ihn also nicht umbiegen, ohne
    Schritt 1 zu brechen. None, wenn der Umschlag keinen brauchbaren Namen
    fuehrt - dann gibt es nichts, wonach neben dem Paket zu suchen waere.
    """
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        return None
    ref = envelope["payload"].get("reference")
    if not isinstance(ref, str):
        return None
    name = ref.rstrip("/").rsplit("/", 1)[-1]
    if name in ("", ".", "..") or "\\" in name or "\x00" in name:
        return None
    return name


def _inhaltsdatei_lesen(package: Dict[str, Any], verzeichnis: str) -> None:
    """Liest die Datei(en), die neben der nackten Paketdatei die Nutzlast tragen
    (Schritt 1a). In einer Ablage ersetzt load_bag das Ergebnis durch die
    Sicht ueber ganz data/ (_inhalt_in_ablage).

    Befund der Gate-A-Generalprobe vom 03.10.2026 (S2a, Werk; S2b und
    rotes Team 01 A5a, Akte): gesiegelt ist payload_b64 IM Paket, gelesen
    wird aber die Datei DANEBEN (KRITERIENWERK.md, akte.json). Die wurde
    nirgends gegen den Umschlag gehalten; ein Zeichen geaendert, Manifeste
    nachgerechnet, und das Urteil blieb BESTANDEN, auch mit allen drei
    Aussenankern. Gelesen wird hier, geurteilt in verify_package.

    Genommen wird jede Datei im Verzeichnis der Paketdatei, deren Name dem
    Namen aus dem versiegelten Umschlag entspricht, Gross-/Kleinschreibung
    egal (Nachpruefung ap14: "kriterienwerk.md" daneben ist dieselbe Lesedatei
    unter anderem Namen). Ein Lesefehler wird mitgegeben, nicht geworfen.
    """
    name = inhaltsdatei_name(package.get("envelope"))
    if name is None:
        package["_inhalt"] = {"name": None}
        return
    ordner = verzeichnis or "."
    dateien: Dict[str, Any] = {}
    try:
        eintraege = sorted(os.listdir(ordner))
    except OSError:
        eintraege = []
    for fname in eintraege:
        voll = os.path.join(ordner, fname)
        if fname.lower() == name.lower() and os.path.isfile(voll):
            dateien[os.path.join(verzeichnis, fname)] = _lies_bytes(voll)
    package["_inhalt"] = {
        "name": name,
        "ablage": False,
        "pflicht": False,
        "pflicht_pfad": os.path.join(verzeichnis, name),
        "dateien": dateien,
    }


def _lies_bytes(pfad: str) -> Any:
    """Bytes einer Datei, oder der Lesefehler als Text (Befund, kein Abbruch)."""
    try:
        with open(pfad, "rb") as fh:
            return fh.read()
    except OSError as e:
        return f"nicht lesbar: {e}"


def _inhalt_in_ablage(package: Dict[str, Any], bag_dir: str, geliefert: Sequence[str]) -> None:
    """Schritt 1a in einer Ablage: ALLE gelieferten Dateien unter data/, deren
    Basisname (Gross-/Kleinschreibung egal) dem Namen aus payload.reference
    entspricht, und die Pflicht, dass die Inhaltsdatei an der Stelle liegt,
    an der jeder Erzeuger sie ablegt.

    Nachpruefung zu ap14 (gemessen): 1a suchte nur im Ordner der gewaehlten
    Paketdatei. Wer siegel_paket.json nach data/x/ verschob, kam mit
    derselben Faelschung durch ("Datei fehlt: data/x/KRITERIENWERK.md").
    Jetzt zaehlt die Ablage als Ganzes.

    Pflichtstelle: data/<name>. So legen alle drei Erzeuger ab
    (werk_versiegeln.py: data/KRITERIENWERK.md, belegakte_build/
    belegakte_bagit: data/akte.json, seal_export.py: data/response.json),
    und zwar immer dann, wenn das Paket payload_b64 traegt. Nur dann ist die
    Datei Pflicht; ohne payload_b64 gibt es keine Nutzlast im Paket, die der
    Erzeuger daneben ablegen koennte.

    Bewusst OHNE Ausnahme fuer Unterordner mit eigenem Siegelpaket: sonst
    legte ein Faelscher eine Paketdatei neben seine Kopie und naehme sie aus.
    Die Demo-Akte der Referenzakte (data/stufen/stufe_b/akte.json) ist mit
    der Nutzlast byte-gleich und besteht deshalb (gemessen).
    """
    name = inhaltsdatei_name(package.get("envelope"))
    if name is None:
        package["_inhalt"] = {"name": None}
        return
    dateien: Dict[str, Any] = {}
    for rel in sorted(geliefert):
        if os.path.basename(rel).lower() != name.lower():
            continue
        dateien[rel] = _lies_bytes(os.path.join(bag_dir, rel))
    package["_inhalt"] = {
        "name": name,
        "ablage": True,
        "pflicht": package.get("payload_b64") is not None,
        "pflicht_pfad": f"data/{name}",
        "dateien": dateien,
    }


def _bag_manifest_entries(path: str, name: str) -> List[Tuple[str, str]]:
    """Zeilen '<sha256-hex>  <relpfad>' einer (tag)manifest-Datei, strikt gelesen."""
    entries: List[Tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2 or not _SHA256_RE.match(parts[0]):
                    raise PaketFehler(f"{name}, Zeile {lineno}: '<sha256>  <pfad>' erwartet")
                entries.append((parts[0], parts[1].strip()))
    except OSError as e:
        raise PaketFehler(f"{name} nicht lesbar: {e}")
    return entries


# Das Manifest ueber den Dateien der Bag-Wurzel. Dieses Skript traegt genau
# ein Verfahren (SHA-256); der Name steht als Konstante, weil Schritt 0 ihn
# an drei Stellen braucht - lesen, ausnehmen, begruenden.
TAGMANIFEST_NAME = "tagmanifest-sha256.txt"


def _bag_wurzel_dateien(bag_dir: str) -> List[str]:
    """
    Jede Datei der Ablage AUSSERHALB von data/ (RFC 8493 nennt sie
    Tag-Dateien), relativ zur Bag-Wurzel und in fester Reihenfolge.

    Unterverzeichnisse zaehlen mit: was neben data/ liegt, wird mit
    ausgeliefert, egal wie tief es liegt (V5-F3, #166).
    """
    dateien: List[str] = []
    for root, dirs, files in os.walk(bag_dir):
        if os.path.abspath(root) == os.path.abspath(bag_dir) and "data" in dirs:
            dirs.remove("data")
        for fname in files:
            # Ein Verweis ist schon Befund (_verweise_in_ablage); als Tag-Datei
            # gezaehlt und gelesen wird er nicht.
            if os.path.islink(os.path.join(root, fname)):
                continue
            rel = os.path.relpath(os.path.join(root, fname), bag_dir).replace(os.sep, "/")
            dateien.append(rel)
    return sorted(dateien)


# Die Tag-Dateien der Wurzel, die load_bag selbst oeffnet. Liegt eine davon als
# Verweis vor, wird sie trotzdem gelesen; der Befundtext sagt das (#352).
_WURZEL_TAGDATEIEN_GELESEN = ("bagit.txt", "manifest-sha256.txt", TAGMANIFEST_NAME,
                              "bag-info.txt")


def _verweise_in_ablage(bag_dir: str) -> List[str]:
    """
    Jeder symbolische Verweis in der Ablage, Datei oder Ordner, in data/
    ebenso wie in der Bag-Wurzel, relativ zur Bag-Wurzel (#352).

    os.walk folgt Ordner-Verweisen per Vorgabe nicht. Bis hierher hiess das:
    ein Ordner-Verweis unter data/ wurde weder gelesen noch gemeldet, und
    Schritt 0 schrieb trotzdem "Vollstaendigkeit unter data/ geprueft". Die
    beiden naheliegenden Reparaturen sind beide falsch: still ueberspringen
    behauptet weiter eine Pruefung, die nicht stattfand, und blind folgen
    verschiebt die Frage nur ans Ziel, das ausserhalb der Ablage liegen kann
    (Pfadflucht). Eine Ablage nach RFC 8493 braucht keine Verweise; jeder
    ist deshalb ein Befund, und gelesen wird durch keinen hindurch.

    Grenze: Windows-Verzeichnisverbindungen (Junctions) erkennt
    os.path.islink nicht; dieses Skript bleibt bei Python 3.8 und prueft sie
    nicht.
    """
    verweise: List[str] = []
    for root, dirs, files in os.walk(bag_dir):
        for name in list(dirs) + list(files):
            voll = os.path.join(root, name)
            if os.path.islink(voll):
                verweise.append(os.path.relpath(voll, bag_dir).replace(os.sep, "/"))
    return sorted(verweise)


def _hinter_verweis(rel: str, verweise: Sequence[str]) -> Optional[str]:
    """Der Verweis, durch den der Ablagepfad rel fuehrt (er selbst oder ein
    Ordner davor), sonst None."""
    for v in verweise:
        if rel == v or rel.startswith(v + "/"):
            return v
    return None


def _pfad_flieht(rel: str) -> bool:
    """Ein Manifest-Pfad, der aus der Ablage herausfuehren kann: absolut, mit
    '..'-Glied oder mit Rueckstrich. Gelesen wird so ein Pfad nicht."""
    if not rel or rel.startswith("/") or "\\" in rel or re.match(r"^[A-Za-z]:", rel):
        return True
    return any(teil == ".." for teil in rel.split("/"))


def _bag_info_felder(pfad: str) -> Optional[List[Tuple[str, str]]]:
    """
    bag-info.txt als Folge von (Label, Wert), RFC 8493 Abschnitt 2.2.2.

    Fortsetzungszeilen beginnen mit Leerraum und gehoeren zum Wert der
    vorangehenden Zeile. Ein Label darf mehrfach vorkommen, deshalb eine
    Liste und kein Dict - zwei Zeilen mit demselben Label und verschiedenen
    Werten sind ein Widerspruch, den Schritt 0b sehen muss, statt ihn beim
    Einlesen zu verlieren. None, wenn es die Datei nicht gibt (sie ist
    optional).
    """
    if not os.path.isfile(pfad):
        return None
    felder: List[Tuple[str, str]] = []
    try:
        with open(pfad, "r", encoding="utf-8") as fh:
            for zeile in fh:
                zeile = zeile.rstrip("\n")
                if not zeile.strip():
                    continue
                if zeile[:1] in (" ", "\t") and felder:
                    label, wert = felder[-1]
                    felder[-1] = (label, f"{wert} {zeile.strip()}")
                    continue
                label, sep, wert = zeile.partition(":")
                if not sep:
                    continue
                felder.append((label.strip(), wert.strip()))
    except OSError as e:
        raise PaketFehler(f"bag-info.txt nicht lesbar: {e}")
    return felder


# Die Felder in bag-info.txt, die eine Kopie von etwas SIGNIERTEM sind
# (S6-F3, #149). Je Feld: Quelle ("umschlag" oder "siegel"), Weg dorthin und
# die Vergleichsart. Genau diese Kopien lassen sich binden - alles andere in
# der Bag-Wurzel ist Ablage-Verwaltung und wird im Befundtext als ungedeckt
# benannt, statt stillschweigend mitgemeint zu sein.
#
# "anfang" statt "gleich" gibt es fuer genau einen Fall: das Werk-Paket (V5,
# #133) schreibt PHM-Werk als "<Titel>, Fassung <n>", und der versiegelte
# origin.description faengt mit genau diesem Satz an und fuehrt danach weiter
# aus. Der Vergleich prueft also, dass die Kurzfassung in der Bag-Wurzel der
# Anfang der versiegelten Langfassung ist - keine freie Aehnlichkeit.
BAG_INFO_GEDECKT: Dict[str, Tuple[str, Tuple[str, ...], str]] = {
    "PHM-Stichtag": ("umschlag", ("as_of", "timestamp"), "gleich"),
    "PHM-Erstellt-Am": ("umschlag", ("created_at",), "gleich"),
    "PHM-Akte-Version": ("umschlag", ("method", "version"), "gleich"),
    "PHM-Akte-Typ": ("umschlag", ("method", "id"), "gleich"),
    "PHM-Sealed-At": ("siegel", ("sealed_at",), "gleich"),
    "PHM-Werk": ("umschlag", ("origin", "description"), "anfang"),
}


def _feld_pfad(wurzel: Any, pfad: Sequence[str]) -> Optional[str]:
    """Wert eines verschachtelten Feldes, None wenn es ihn nicht gibt."""
    knoten: Any = wurzel
    for teil in pfad:
        if not isinstance(knoten, dict) or teil not in knoten:
            return None
        knoten = knoten[teil]
    return None if knoten is None else str(knoten)


# Dateien, die erst NACH dem Siegeln entstehen und deshalb nicht in der
# mitversiegelten Auslieferungsliste stehen koennen.
#
# ACHTUNG, das war bis S6-F1 (#144) eine UNBEDINGTE Ausnahme in Schritt 1b -
# und damit eine Luecke: wer Dateizugriff hatte, konnte unter genau diesen
# Namen ablegen, was er wollte. Die Namen stehen hier nur noch, damit
# load_bag den Archiv-Nachweis findet und der Gleichlauf mit dem Erzeuger
# pruefbar bleibt. Ausgenommen wird in 1b jetzt ausschliesslich, was die
# nachgelagerte Liste (nachtrag.json) fuehrt - und die prueft Schritt 1c.
NACH_DEM_SIEGELN = ("data/archiv_nachweis.json", "archiv_nachweis.json",
                    "data/nachtrag.json", "nachtrag.json")

# Die nachgelagerte Auslieferungsliste (S6-F1, #144). Zweite Implementierung
# derselben Spec wie backend/tools/belegakte_build.py - absichtlich nicht
# importiert: der Verifier muss ohne unseren Code auskommen, und zwei
# Umsetzungen decken auf, was eine allein fuer selbstverstaendlich haelt
# (so gefunden im auftrag-Feld, DECISIONS 31.07.).
NACHTRAG_PFADE = ("data/nachtrag.json", "nachtrag.json")
NACHTRAG_VERSION = "1"
_NACHTRAG_SIGNED_FIELDS = (
    "nachtrag_version",
    "sig_algo",
    "hash_algo",
    "key_id",
    "erstellt_am",
    "siegel_paket_sha256",
    "eintraege_pruefsumme",
)


def nachtrag_signed_bytes(record: Any) -> bytes:
    """Signierte Serialisierung der nachgelagerten Liste v1 (Zweitimplementierung)."""
    if not isinstance(record, dict):
        raise PaketFehler("nachtrag: Objekt erwartet")
    if record.get("nachtrag_version") != NACHTRAG_VERSION:
        raise PaketFehler(
            f"nachtrag_version: nur {NACHTRAG_VERSION!r} wird von dieser Implementierung "
            f"getragen, gelesen {record.get('nachtrag_version')!r}")
    if record.get("sig_algo") != "ed25519" or record.get("hash_algo") != "sha256":
        raise PaketFehler("nachtrag: nur sig_algo ed25519 und hash_algo sha256 werden getragen")
    werte: List[str] = []
    for name in _NACHTRAG_SIGNED_FIELDS:
        wert = record.get(name)
        if not isinstance(wert, str) or not wert:
            raise PaketFehler(f"nachtrag.{name}: nicht-leerer Text erwartet")
        if "\n" in wert:
            raise PaketFehler(f"nachtrag.{name}: Zeilenumbruch ist in der Serialisierung unzulaessig")
        werte.append(f"{name}:{wert}")
    return "\n".join(werte).encode("utf-8")


def nachtrag_eintraege_pruefsumme(eintraege: Any) -> str:
    """SHA-256 ueber die kanonische Fassung der Eintragsliste (Zweitimplementierung)."""
    if not isinstance(eintraege, list):
        raise PaketFehler("nachtrag.eintraege: Liste erwartet")
    kanonisch: List[Dict[str, str]] = []
    for i, e in enumerate(eintraege):
        if not isinstance(e, dict):
            raise PaketFehler(f"nachtrag.eintraege[{i}]: Objekt erwartet")
        pfad, soll = e.get("pfad"), e.get("sha256")
        if not isinstance(pfad, str) or not pfad:
            raise PaketFehler(f"nachtrag.eintraege[{i}]: 'pfad' fehlt oder ist kein Text")
        if not isinstance(soll, str) or not _SHA256_RE.match(soll):
            raise PaketFehler(
                f"nachtrag.eintraege[{i}] ({pfad}): 'sha256' fehlt oder ist keine "
                "64-stellige Hex-Prueffsumme")
        kanonisch.append({"pfad": pfad, "sha256": soll})
    return hashlib.sha256(
        json.dumps(kanonisch, sort_keys=True, ensure_ascii=False,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def load_bag(bag_dir: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Liest eine BagIt-Ablage (RFC 8493): prueft bagit.txt, rechnet jede in
    manifest-sha256.txt genannte Prueffsumme nach, verlangt Vollstaendigkeit
    (jede Datei unter data/ ist im Manifest) und prueft, wenn vorhanden,
    tagmanifest-sha256.txt - dieses ebenfalls auf Vollstaendigkeit, also
    jede Datei der Bag-Wurzel gegen das Tagmanifest (V5-F3, #166). Liefert
    (Paket, Pruefschritt-0-Ergebnis).

    Dieselbe Prueffsummen-Kontrolle geht auch OHNE dieses Skript mit
    Standard-Werkzeugen, dann aber mit BEIDEN Zeilen im Ablage-Verzeichnis:
    `shasum -a 256 --check manifest-sha256.txt` und `shasum -a 256 --check
    tagmanifest-sha256.txt`. Die erste allein deckt das Manifest nicht, das
    sie benutzt (#165). Strukturell Unbrauchbares (keine bagit.txt, kein
    Manifest, kein Paket) ist PaketFehler (Exit 2); eine falsche Prueffsumme
    ist ein BEFUND (Schritt 0 nicht bestanden), die uebrigen Schritte
    laufen trotzdem.
    """
    bagit_txt = os.path.join(bag_dir, "bagit.txt")
    if not os.path.isfile(bagit_txt):
        raise PaketFehler(f"keine BagIt-Ablage: {bagit_txt} fehlt")
    try:
        with open(bagit_txt, "r", encoding="utf-8") as fh:
            first = fh.readline()
    except OSError as e:
        raise PaketFehler(f"bagit.txt nicht lesbar: {e}")
    if not first.startswith("BagIt-Version:"):
        raise PaketFehler("bagit.txt: erste Zeile muss mit 'BagIt-Version:' beginnen")

    manifest = _bag_manifest_entries(os.path.join(bag_dir, "manifest-sha256.txt"), "manifest-sha256.txt")
    if not manifest:
        raise PaketFehler("manifest-sha256.txt: leer")
    findings: List[str] = []
    # #352: Verweise zuerst, damit kein Schritt unten durch einen hindurch
    # liest. Jeder ist ein eigener Befund mit Pfad und Ziel.
    verweise = _verweise_in_ablage(bag_dir)
    for v in verweise:
        try:
            ziel = os.readlink(os.path.join(bag_dir, v))
        except OSError as e:
            ziel = f"nicht lesbar: {e}"
        if v in _WURZEL_TAGDATEIEN_GELESEN:
            # Diese Tag-Dateien liest Schritt 0 selbst, um die Ablage
            # ueberhaupt zu oeffnen (os.path.isfile/open folgen dem Verweis).
            # Gelesen wird hier also doch durch ihn hindurch; das sagt der
            # Befund, statt das Gegenteil zu behaupten.
            wie = ("als Tag-Datei liest dieser Schritt sie trotzdem, um die Ablage zu "
                   "oeffnen; ihr Inhalt stammt damit von ausserhalb der Ablage")
        else:
            wie = "er wird weder verfolgt noch uebersprungen, durch ihn wird nichts gelesen"
        findings.append(
            f"{v}: symbolischer Verweis (Ziel {ziel!r}) - in einer Ablage ist das ein Befund; {wie}")
    for want_hash, rel in manifest:
        if _pfad_flieht(rel):
            findings.append(f"{rel}: Pfad fuehrt aus der Ablage heraus, nicht gelesen")
            continue
        if not rel.startswith("data/"):
            findings.append(f"{rel}: Nutzdaten muessen unter data/ liegen")
            continue
        durch = _hinter_verweis(rel, verweise)
        if durch is not None:
            findings.append(f"{rel}: liegt hinter dem symbolischen Verweis {durch}, nicht gelesen")
            continue
        full = os.path.join(bag_dir, rel)
        if not os.path.isfile(full):
            findings.append(f"{rel}: im Manifest genannt, aber nicht vorhanden")
            continue
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
        if h.hexdigest() != want_hash:
            findings.append(f"{rel}: Prueffsumme passt nicht (Datei veraendert)")
    listed = {rel for _, rel in manifest}
    # Ist data/ selbst ein Verweis, folgte os.walk ihm als Startpunkt doch
    # (nur Unterordner-Verweise laesst es aus). Dann wird data/ nicht begangen.
    data_ist_verweis = "data" in verweise
    for root, _dirs, files in ([] if data_ist_verweis else os.walk(os.path.join(bag_dir, "data"))):
        for fname in files:
            if os.path.islink(os.path.join(root, fname)):
                continue  # schon Befund, siehe oben
            rel = os.path.relpath(os.path.join(root, fname), bag_dir).replace(os.sep, "/")
            if rel not in listed:
                findings.append(f"{rel}: liegt unter data/, steht aber nicht im Manifest")

    # V5-F3 (#166): bis hierher deckte die Vollstaendigkeitspruefung nur data/.
    # Eine Datei NEBEN data/ fiel unter kein Manifest und lief still durch -
    # die Zusage aus B6 ("was ausgeliefert wird, ist gedeckt") galt damit
    # strukturell eine Ebene tief. Ausgeliefert wird aber die ganze Ablage.
    # Die Deckung der Wurzel leistet das Tagmanifest, und zwar in BEIDE
    # Richtungen: jede genannte Datei nachgerechnet (das gab es schon) und
    # jede vorhandene Datei genannt (das ist neu).
    tagmanifest_path = os.path.join(bag_dir, TAGMANIFEST_NAME)
    wurzel_dateien = _bag_wurzel_dateien(bag_dir)
    # Was dieser Schritt WIRKLICH getan hat, als Befehlszeilen fuer den, der es
    # ohne dieses Skript nachvollziehen will. Frueher stand hier unbedingt nur
    # die Manifest-Zeile - und die ist NICHT dieselbe Kontrolle: wer eine
    # Nutzdatei und das Manifest zusammen umschreibt, kommt an ihr allein
    # vorbei (#165).
    ohne_skript = "shasum -a 256 --check manifest-sha256.txt"
    if os.path.isfile(tagmanifest_path):
        ohne_skript += (
            " UND shasum -a 256 --check tagmanifest-sha256.txt - beide Zeilen, "
            "die erste allein deckt das Manifest nicht, das sie benutzt"
        )
        tag_eintraege = _bag_manifest_entries(tagmanifest_path, TAGMANIFEST_NAME)
        for want_hash, rel in tag_eintraege:
            if _pfad_flieht(rel):
                findings.append(f"{rel}: Pfad im Tagmanifest fuehrt aus der Ablage heraus, nicht gelesen")
                continue
            durch = _hinter_verweis(rel, verweise)
            if durch is not None:
                findings.append(f"{rel}: liegt hinter dem symbolischen Verweis {durch}, nicht gelesen")
                continue
            full = os.path.join(bag_dir, rel)
            if not os.path.isfile(full):
                findings.append(f"{rel}: im Tagmanifest genannt, aber nicht vorhanden")
                continue
            with open(full, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != want_hash:
                    findings.append(f"{rel}: Tag-Prueffsumme passt nicht (Datei veraendert)")
        # Ausgenommen ist genau eine Datei: das Tagmanifest selbst. Es kann
        # seine eigene Prueffsumme nicht fuehren - die stuende in der Datei,
        # die sie beschreibt. Ein Tagmanifest in einem ANDEREN Verfahren ist
        # nicht ausgenommen: dieses Skript prueft es nicht, also ist es
        # ungedeckt wie jede andere Datei auch (und wer schmuggeln will,
        # soll sich nicht durch einen Dateinamen ausnehmen koennen).
        tag_gelistet = {rel for _, rel in tag_eintraege}
        for rel in wurzel_dateien:
            if rel != TAGMANIFEST_NAME and rel not in tag_gelistet:
                findings.append(
                    f"{rel}: liegt in der Bag-Wurzel, steht aber nicht im Tagmanifest")
        tag_note = (
            f"{TAGMANIFEST_NAME} geprueft, und die Bag-Wurzel dagegen auf Vollstaendigkeit "
            f"gehalten ({len(wurzel_dateien)} Datei(en) ausserhalb von data/; ausgenommen ist "
            f"nur {TAGMANIFEST_NAME} selbst, das seine eigene Prueffsumme nicht fuehren kann)"
        )
    else:
        # Ohne Tagmanifest gibt es nichts, wogegen die Wurzel zu halten waere.
        # Dann wird die Grenze nicht bloss benannt, sondern es werden die
        # ungedeckten Dateien AUFGEZAEHLT: wer eine dazulegt, steht damit
        # auch in diesem Fall im Befundtext.
        tag_note = (
            f"kein {TAGMANIFEST_NAME} (nach RFC 8493 optional) - die Bag-Wurzel ist damit "
            "durch nichts gedeckt; ungedeckt liegen dort: "
            + (", ".join(wurzel_dateien) if wurzel_dateien else "keine Datei")
        )

    # S6-F3 (#149): die Tag-Dateien der Bag-Wurzel liegen ausserhalb von data/
    # und damit ausserhalb der Auslieferungsliste. bag-info.txt ist davon die
    # inhaltlich relevante: sie traegt PHM-Stichtag - die Aussage, auf die
    # sich die ganze Akte bezieht. Gelesen wird sie hier, gehalten wird sie in
    # Schritt 0b gegen den versiegelten Umschlag.
    package_bag_info = _bag_info_felder(os.path.join(bag_dir, "bag-info.txt"))

    # Eine Paketdatei hinter einem Verweis oder mit fluechtigem Pfad ist kein
    # Kandidat: gelesen wird durch keinen Verweis hindurch (#352).
    candidates = [rel for rel in sorted(listed)
                  if os.path.basename(rel).startswith("siegel_paket") and rel.endswith(".json")
                  and not _pfad_flieht(rel) and _hinter_verweis(rel, verweise) is None]
    # Ein ausgeliefertes Bag kann mehr als ein Paket enthalten: die Belegakte
    # traegt unter data/stufen/ bewusst Demomaterial mit (Faelschungs-
    # Experimente zum Selbstnachstellen). Regel deshalb: genau ein Kandidat
    # wird genommen; bei mehreren gilt das Paket an der kanonischen Stelle
    # data/siegel_paket.json. Nur wenn auch die fehlt, ist die Eingabe
    # mehrdeutig - dann Abbruch, nie geraten. (Befund der Gate-A-Probe
    # 30.07.2026: ohne diese Regel war die ausgelieferte Akte mit dem
    # eigenen Verifier nicht pruefbar, docs/GATE_A_NACHWEIS.md.)
    KANONISCH = "data/siegel_paket.json"
    # Nutzdaten in UNTERverzeichnissen sind Beilage (die Belegakte fuehrt
    # unter data/stufen/ Demomaterial mit), nicht das zu pruefende Paket.
    oben = [rel for rel in candidates if rel.count("/") == 1]
    if len(candidates) == 1:
        gewaehlt = candidates[0]
    elif len(oben) == 1:
        gewaehlt = oben[0]
    elif KANONISCH in oben:
        gewaehlt = KANONISCH
    else:
        raise PaketFehler(
            "erwartet ist genau eine Paketdatei direkt unter data/ (oder "
            f"data/siegel_paket.json), gefunden: {candidates or 'keine'}"
            + (f"; nicht gelesen, weil hinter symbolischen Verweisen: {', '.join(verweise)} "
               "(#352: durch einen Verweis wird nicht gelesen)" if verweise else "")
        )
    package = load_package(os.path.join(bag_dir, gewaehlt))
    # Nachpruefung ap14: die Paketdatei liegt bei jedem Erzeuger DIREKT unter
    # data/ (werk_versiegeln, belegakte_bagit: data/siegel_paket.json;
    # seal_export: data/siegel_paket_<id>.json). Eine Paketdatei weiter unten
    # ist nicht, was ein Erzeuger schreibt, sondern eine verschobene - und das
    # Verschieben war der Weg an Schritt 1a vorbei. Gelesen und geprueft wird
    # sie trotzdem (sonst saehe der Pruefer nichts), aber Schritt 0 faellt.
    if gewaehlt.count("/") != 1:
        findings.append(
            f"{gewaehlt}: die Paketdatei liegt nicht direkt unter data/, wo jeder Erzeuger "
            "sie ablegt; eine verschobene Paketdatei ist ein Befund")

    # S6/A5 (#116): die TATSAECHLICH gelieferten Dateien mitgeben, gerechnet
    # aus den Dateien selbst und nicht aus dem Manifest. Das Manifest kann der
    # Faelscher nachziehen; die versiegelte Auslieferungsliste im Umschlag
    # kann er ohne Schluessel nicht.
    geliefert: Dict[str, str] = {}
    for root, _dirs, files in ([] if data_ist_verweis else os.walk(os.path.join(bag_dir, "data"))):
        for fname in files:
            voll = os.path.join(root, fname)
            if os.path.islink(voll):
                continue  # Befund in Schritt 0, nicht als geliefert gelesen
            rel = os.path.relpath(voll, bag_dir).replace(os.sep, "/")
            h = hashlib.sha256()
            with open(voll, "rb") as fh:
                for block in iter(lambda: fh.read(65536), b""):
                    h.update(block)
            geliefert[rel] = h.hexdigest()
    package["_geliefert"] = geliefert
    package["_paketdatei"] = gewaehlt
    _inhalt_in_ablage(package, bag_dir, list(geliefert))
    package["_bag_info"] = package_bag_info

    # Die nachgelagerte Liste (S6-F1, #144). Gelesen wird sie hier, geurteilt
    # in Schritt 1c. Ein Lesefehler ist ein Befund, kein Abbruch: eine
    # unlesbare Datei an dieser Stelle ist genau das, was ein Angreifer
    # hinterlaesst, der die Liste loswerden will.
    for kandidat in NACHTRAG_PFADE:
        if kandidat not in geliefert:
            continue
        package["_nachtrag_pfad"] = kandidat
        try:
            with open(os.path.join(bag_dir, kandidat), "r", encoding="utf-8") as fh:
                roh = json.load(fh)
            if not isinstance(roh, dict):
                raise PaketFehler("JSON-Objekt erwartet")
            package["_nachtrag"] = roh
        except OSError as e:
            package["_nachtrag_fehler"] = f"nicht lesbar: {e}"
        except ValueError as e:
            package["_nachtrag_fehler"] = f"kein gueltiges JSON: {e}"
        except PaketFehler as e:
            package["_nachtrag_fehler"] = str(e)
        break

    # Folgepunkt zur Nachpruefung 02.08.2026: Schritt 1b nimmt den
    # Archiv-Zugehoerigkeitsnachweis aus, weil er erst nach dem Siegeln
    # entsteht. Damit die Ausnahme keine Luecke ist, muss der Nachweis im
    # Paketpfad SELBST geprueft werden. Gelesen wird er hier, geurteilt wird
    # in Schritt 1d. Ein Lesefehler wird mitgegeben statt geworfen: eine
    # unlesbare Datei an dieser Stelle ist ein Befund, kein Abbruch der
    # ganzen Pruefung.
    for kandidat in NACH_DEM_SIEGELN:
        if kandidat not in geliefert:
            continue
        package["_archiv_nachweis_pfad"] = kandidat
        try:
            package["_archiv_nachweis"] = load_archive_proof(
                os.path.join(bag_dir, kandidat)
            )
        except PaketFehler as e:
            package["_archiv_nachweis_fehler"] = str(e)
        break

    if findings:
        check = _check(
            "0. BagIt-Ablage (RFC 8493): Prueffsummen",
            NICHT_BESTANDEN,
            "; ".join(findings),
        )
    else:
        check = _check(
            "0. BagIt-Ablage (RFC 8493): Prueffsummen",
            BESTANDEN,
            f"{len(manifest)} Nutzdatei(en) gegen manifest-sha256.txt nachgerechnet, "
            f"Vollstaendigkeit unter data/ geprueft; {tag_note}. Die PRUEFFSUMMEN "
            f"dieses Schritts rechnet auch nach, wer dieses Skript nicht hat: "
            f"{ohne_skript}. Die VOLLSTAENDIGKEIT nicht: `shasum --check` prueft, "
            "was in den Listen steht, und meldet deshalb keine Datei, die jemand "
            "zusaetzlich hineingelegt hat - weder unter data/ noch in der Bag-Wurzel. "
            "Das leistet nur dieser Schritt (V5-F4, #167 - gemessen an beiden Stellen).",
        )
    return package, check


LBL_INHALT = "1a. Inhaltsdatei: gelieferte Datei gegen die versiegelte Nutzlast"


def _pruefe_inhaltsdatei(
    package: Dict[str, Any], envelope: Any, payload_b64: Any,
) -> Tuple[Dict[str, str], List[str]]:
    """Schritt 1a: die gelieferte(n) Inhaltsdatei(en) byte-genau gegen die Nutzlast.

    Gehalten wird gegen payload.sha256 im versiegelten Umschlag (das ist
    die Bindung an Siegel und Anker) und, wenn das Paket payload_b64 traegt,
    zusaetzlich Byte fuer Byte gegen die dekodierte Nutzlast. Jede
    Abweichung ist ein Fehlschlag, kein Hinweis. In einer Ablage ist die
    Inhaltsdatei ausserdem PFLICHT an der Stelle des Erzeugers (data/<name>),
    sobald das Paket payload_b64 traegt: fehlt oder heisst sie anders, ist
    das ein Fehlschlag (Nachpruefung ap14, gemessen: Umbenennen,
    Kleinschreibung, Loeschen kamen sonst mit BESTANDEN durch).

    Eigener Zustand "nicht gemessen": bei der nackten Paketdatei ohne
    gleichnamige Datei daneben (oder einer Ablage ohne payload_b64) gibt es
    nichts, was dem Siegel widersprechen koennte - uebersprungen, und die
    Feststellungsliste fuehrt es als offenen Punkt.

    Liefert (Ergebnis, die geprueften Pfade der Ablage); die Pfade braucht
    die Aufzaehlung der ungedeckten Dateien.
    """
    inhalt = package.get("_inhalt")
    if not isinstance(envelope, dict):
        return _check(
            LBL_INHALT, UEBERSPRUNGEN,
            "kein Umschlag im Paket; ohne ihn gibt es keinen versiegelten Fingerabdruck, gegen "
            "den eine gelieferte Datei zu halten waere."), []
    if inhalt is None:
        return _check(
            LBL_INHALT, UEBERSPRUNGEN,
            "NICHT GEMESSEN: das Paket wurde ohne Dateiablage vorgelegt (kein Verzeichnis, aus "
            "dem es gelesen wurde); eine gelieferte Inhaltsdatei gibt es dann nicht zu "
            "pruefen."), []
    name = inhalt.get("name")
    if not name:
        return _check(
            LBL_INHALT, UEBERSPRUNGEN,
            "NICHT GEMESSEN: der Umschlag nennt in payload.reference keinen Dateinamen; "
            "es laesst sich nicht sagen, welche gelieferte Datei die Nutzlast traegt."), []
    dateien: Dict[str, Any] = inhalt.get("dateien") or {}
    pflicht_pfad = str(inhalt.get("pflicht_pfad"))
    geprueft = sorted(dateien) if inhalt.get("ablage") else []

    spec = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
    soll = spec.get("sha256")
    nutzlast: Optional[bytes] = None
    if payload_b64 is not None:
        try:
            nutzlast = base64.b64decode(str(payload_b64), validate=True)
        except (ValueError, binascii.Error):
            nutzlast = None

    befunde: List[str] = []
    if inhalt.get("pflicht") and pflicht_pfad not in dateien:
        anders = ", ".join(sorted(dateien))
        befunde.append(
            f"{pflicht_pfad} fehlt: an dieser Stelle legt der Erzeuger die versiegelte Nutzlast "
            "ab, und dieses Paket traegt eine (payload_b64). "
            + (f"Unter abweichendem Namen geliefert: {anders}. " if anders else "")
            + "Eine Ablage, deren Lesedatei fehlt oder anders heisst, ist nicht die ausgelieferte")
    for pfad, daten in sorted(dateien.items()):
        if isinstance(daten, str):
            befunde.append(f"{pfad}: {daten}")
            continue
        einzel: List[str] = []
        ist = hashlib.sha256(daten).hexdigest()
        if ist != soll:
            einzel.append(
                f"SHA-256 der gelieferten Datei {ist[:16]}..., versiegelt (payload.sha256 im "
                f"Umschlag) {str(soll)[:16]}...")
        if nutzlast is not None and nutzlast != daten:
            erste = next((i for i, (a, b) in enumerate(zip(daten, nutzlast)) if a != b),
                         min(len(daten), len(nutzlast)))
            einzel.append(
                f"Byte-Vergleich mit payload_b64: {len(daten)} gegen {len(nutzlast)} Bytes, "
                f"erste Abweichung bei Byte {erste}")
        if einzel:
            befunde.append(f"{pfad} ist NICHT die versiegelte Nutzlast: " + "; ".join(einzel))
    if befunde:
        return _check(
            LBL_INHALT, NICHT_BESTANDEN,
            "; ".join(befunde)
            + ". Wer diese Datei liest, liest nicht den Text, den Siegel und Zeitstempel "
            "bezeugen. Die BagIt-Manifeste koennen trotzdem stimmen: sie sind ungezeichnet und "
            "lassen sich nachrechnen (Gate-A-Generalprobe 03.10.2026, S2a/S2b)."), geprueft
    if not dateien:
        if inhalt.get("ablage"):
            text = (
                f"NICHT GEMESSEN, Datei fehlt: die Ablage liefert keine Datei namens {name}, und "
                "das Paket traegt keine Nutzlast (payload_b64), die der Erzeuger daneben "
                "abgelegt haette.")
        else:
            text = (
                f"NICHT GEMESSEN, Datei fehlt: neben der Paketdatei liegt keine {name}. Lesbar "
                "ist dann nur die Nutzlast im Paket selbst (payload_b64, Schritt 1); wer eine "
                "andere Datei als den Text liest, liest etwas, das diese Pruefung nicht deckt.")
        return _check(LBL_INHALT, UEBERSPRUNGEN, text), []
    groessen = ", ".join(f"{p} ({len(d)} Bytes)" for p, d in sorted(dateien.items()))
    return _check(
        LBL_INHALT, BESTANDEN,
        f"{groessen} gegen die versiegelte Nutzlast gehalten: SHA-256 gleich payload.sha256 im "
        "Umschlag"
        + (", und Byte fuer Byte gleich payload_b64" if nutzlast is not None else "")
        + ". Damit ist die gelieferte Datei, nicht nur die Kopie im Paket, an Siegel und "
        "Zeitstempel gebunden. Gesucht wurde "
        + ("in der ganzen Ablage unter data/, Gross-/Kleinschreibung egal."
           if inhalt.get("ablage") else "im Verzeichnis der Paketdatei.")), geprueft


def verify_package(
    package: Dict[str, Any],
    public_key_hex: Optional[str] = None,
    trusted_cert_der: Optional[bytes] = None,
    bag_check: Optional[Dict[str, str]] = None,
    archiv_public_key_hex: Optional[str] = None,
    key_history: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Faehrt die Pruefschritte und liefert {checks, verdict, passed} plus den
    Versions-Ausweis {envelope_version, seal_version} (gegen welche Version
    geprueft wurde). Ein Schritt, dessen Voraussetzung im Paket fehlt, wird
    als uebersprungen ausgewiesen, nie still als bestanden. public_key_hex
    ist der vom Pruefer selbst vorgelegte oeffentliche Schluessel
    (Vertrauensanker, analog trusted_cert_der fuer die TSA); bag_check ist
    das Schritt-0-Ergebnis aus load_bag, wenn die Eingabe eine BagIt-Ablage
    war.

    archiv_public_key_hex ist der Schluessel der ARCHIV-Wochenmanifeste und
    ein anderer als public_key_hex (der Erzeuger leitet ihn eigens ab, siehe
    belegakte_build.lade_archiv_manifest_seed). Er gehoert zu Schritt 1d.
    Ohne ihn prueft 1d den mitgelieferten Nachweis gegen den Schluessel IM
    Nachweis, und der Befundtext sagt das auch: wer den Nachweis erfunden
    hat, hat dann auch den Schluessel dazu erfunden.
    """
    checks: List[Dict[str, str]] = []
    seal = package["seal"]
    envelope = package.get("envelope")

    # Schritt 0: BagIt-Ablage (nur wenn die Eingabe eine war)
    checks.append(
        bag_check
        or _check(
            "0. BagIt-Ablage (RFC 8493): Prueffsummen",
            UEBERSPRUNGEN,
            "Eingabe ist die nackte Paketdatei, keine BagIt-Ablage; es gibt keine "
            "Manifest-Prueffsummen zu kontrollieren.",
        )
    )

    # Schritt 0b: die Angaben in bag-info.txt gegen den versiegelten Umschlag
    # (S6-F3, #149).
    #
    # Die Auslieferungsliste aus 1b deckt nur data/. bag-info.txt liegt in der
    # Bag-Wurzel und traegt trotzdem Inhalt: PHM-Stichtag ist die Aussage, auf
    # die sich die ganze Akte bezieht. Wer ihn aendert und
    # tagmanifest-sha256.txt nachrechnet, kam bisher durch - im Befundtext
    # stand die Einschraenkung ehrlich drin, aber ein Empfaenger, der den
    # Stichtag liest, las ein ungedecktes Feld.
    #
    # Die Deckung braucht weder eine neue Datei noch eine zweite Liste: JEDES
    # dieser Felder ist die Kopie eines Wertes, der im versiegelten Umschlag
    # steht. Geprueft wird deshalb die Kopie gegen das Original.
    lbl_info = "0b. bag-info.txt: Angaben gegen den versiegelten Umschlag"
    bag_info = package.get("_bag_info")
    if bag_info is None:
        checks.append(
            _check(
                lbl_info,
                UEBERSPRUNGEN,
                "keine bag-info.txt vorgelegt (Eingabe ist die nackte Paketdatei, oder die "
                "Ablage fuehrt keine). Die Datei ist nach RFC 8493 optional; ohne sie gibt es "
                "keine Angabe in der Bag-Wurzel, die dem Umschlag widersprechen koennte.",
            )
        )
    elif not isinstance(envelope, dict):
        checks.append(
            _check(
                lbl_info,
                UEBERSPRUNGEN,
                "kein Umschlag im Paket; ohne ihn gibt es keine versiegelte Fassung, gegen "
                "die die Angaben in bag-info.txt zu halten waeren.",
            )
        )
    else:
        info_befunde: List[str] = []
        geprueft: List[str] = []
        gesehen: Dict[str, str] = {}
        for label, wert in bag_info:
            if label in gesehen and gesehen[label] != wert:
                info_befunde.append(
                    f"{label}: kommt zweimal mit verschiedenen Werten vor "
                    f"({gesehen[label]!r} und {wert!r}) - ein Widerspruch, keine Praezisierung"
                )
                continue
            gesehen.setdefault(label, wert)
            if label in BAG_INFO_GEDECKT:
                quelle, pfad, art = BAG_INFO_GEDECKT[label]
                soll = _feld_pfad(envelope if quelle == "umschlag" else seal, pfad)
                quelle_text = "der versiegelte Umschlag" if quelle == "umschlag" else "das Siegel"
                if soll is None:
                    info_befunde.append(
                        f"{label}: {quelle_text} fuehrt das zugehoerige Feld nicht, die Angabe "
                        "ist damit durch nichts gedeckt"
                    )
                elif (wert != soll) if art == "gleich" else not soll.startswith(wert):
                    info_befunde.append(
                        f"{label}: die Ablage sagt {wert!r}, {quelle_text} sagt {soll!r}"
                    )
                else:
                    geprueft.append(label)
            elif label.startswith("PHM-"):
                # Ein PHM-Feld, das dieser Verifier nicht kennt, ist eine
                # Aussage von uns, die niemand nachrechnet - dieselbe Klasse
                # wie eine zusaetzlich gelieferte Datei in Schritt 1b.
                info_befunde.append(
                    f"{label}: PHM-Feld, das keine versiegelte Entsprechung hat. Eine Angabe "
                    "unter unserem Namen, die das Siegel nicht deckt, gehoert nicht in die "
                    "Auslieferung"
                )
        if info_befunde:
            checks.append(_check(lbl_info, NICHT_BESTANDEN, "; ".join(info_befunde)))
        elif not geprueft:
            checks.append(
                _check(
                    lbl_info,
                    UEBERSPRUNGEN,
                    "bag-info.txt fuehrt keine PHM-Angabe; die uebrigen Felder (Bagging-Date, "
                    "Payload-Oxum, Source-Organization, External-Identifier) sind "
                    "Ablage-Verwaltung und haben im Umschlag keine Entsprechung.",
                )
            )
        else:
            checks.append(
                _check(
                    lbl_info,
                    BESTANDEN,
                    f"{len(geprueft)} Angabe(n) aus der Bag-Wurzel gegen den versiegelten "
                    f"Umschlag gehalten ({', '.join(sorted(geprueft))}): identisch. Damit ist "
                    "der Stichtag, auf den sich die Akte bezieht, auch ausserhalb von data/ "
                    "gedeckt. NICHT gedeckt bleiben die Verwaltungsfelder der Ablage "
                    "(Bagging-Date, Payload-Oxum, Source-Organization, External-Identifier); "
                    "sie treffen keine Aussage ueber den Inhalt.",
                )
            )

    # Schritt 2 zuerst rechnen, denn Schritte 1, 4 und 5 haengen am
    # nachgerechneten seal_hash; ausgegeben wird in Spec-Reihenfolge.
    recomputed_hash: Optional[str] = None
    try:
        recomputed_hash = recompute_seal_hash(seal)
        if seal.get("seal_hash") != recomputed_hash:
            raise PruefungGescheitert(
                "seal_hash im Paket passt nicht zum nachgerechneten Wert "
                f"(erwartet {recomputed_hash}, im Paket {seal.get('seal_hash')})"
            )
        seal_check = _check(
            "2. Siegel: signierte Serialisierung + seal_hash",
            BESTANDEN,
            f"seal_hash aus Inhalt und Signatur nachgerechnet: {recomputed_hash}",
        )
    except PruefungGescheitert as e:
        seal_check = _check("2. Siegel: signierte Serialisierung + seal_hash", NICHT_BESTANDEN, str(e))

    # Schritt 1: Umschlag + Payload (envelope steht schon oben, Schritt 0b
    # haelt bag-info.txt dagegen)
    payload_b64 = package.get("payload_b64")
    if envelope is None:
        checks.append(
            _check(
                "1. Umschlag: kanonische Serialisierung + Hash",
                UEBERSPRUNGEN,
                "Paket enthaelt keinen Umschlag; geprueft werden dann nur Siegel, Anker und Baum. "
                f"Der envelope_hash im Siegel benennt den Umschlag (Version "
                f"{seal.get('envelope_version')}), ohne ihn vorzulegen.",
            )
        )
    else:
        try:
            env_hash = envelope_sha256(envelope)
            if env_hash != seal.get("envelope_hash"):
                raise PruefungGescheitert(
                    "der vorgelegte Umschlag ist nicht der versiegelte "
                    f"(nachgerechnet {env_hash}, im Siegel {seal.get('envelope_hash')})"
                )
            if envelope.get("envelope_version") != seal.get("envelope_version"):
                raise PruefungGescheitert("envelope_version: Umschlag und Siegel passen nicht zusammen")
            detail = (
                f"kanonische Bytes in der Serialisierung der Version "
                f"{envelope.get('envelope_version')} reproduziert, SHA-256 {env_hash} "
                "stimmt mit dem Siegel ueberein"
            )
            if payload_b64 is not None:
                try:
                    payload_bytes = base64.b64decode(str(payload_b64), validate=True)
                except (ValueError, binascii.Error):
                    raise PruefungGescheitert("payload_b64: keine gueltige Base64-Kodierung")
                payload_sha = hashlib.sha256(payload_bytes).hexdigest()
                spec = envelope.get("payload", {})
                if payload_sha != spec.get("sha256"):
                    raise PruefungGescheitert(
                        "Payload-Bytes passen nicht zum Umschlag "
                        f"(nachgerechnet {payload_sha}, im Umschlag {spec.get('sha256')})"
                    )
                if spec.get("size_bytes") is not None and spec["size_bytes"] != len(payload_bytes):
                    raise PruefungGescheitert(
                        f"Payload-Groesse passt nicht ({len(payload_bytes)} Bytes, "
                        f"im Umschlag {spec['size_bytes']})"
                    )
                detail += f"; Payload ({len(payload_bytes)} Bytes) gegen payload.sha256 geprueft"
            else:
                detail += "; keine Payload im Paket, payload.sha256 benennt den Inhalt ungeprueft"
            checks.append(_check("1. Umschlag: kanonische Serialisierung + Hash", BESTANDEN, detail))
        except PruefungGescheitert as e:
            checks.append(_check("1. Umschlag: kanonische Serialisierung + Hash", NICHT_BESTANDEN, str(e)))

    inhalt_check, inhalt_pfade = _pruefe_inhaltsdatei(package, envelope, payload_b64)
    checks.append(inhalt_check)

    checks.append(seal_check)

    # Schritt 3: Signatur (Ed25519, oeffentlicher Schluessel)
    package_key = package.get("public_key")
    check_key = public_key_hex or (str(package_key) if package_key else None)
    if check_key is None:
        checks.append(
            _check(
                "3. Signatur (Ed25519)",
                UEBERSPRUNGEN,
                "kein oeffentlicher Schluessel: weder vorgelegt (--public-key) noch im Paket. "
                "Der Schluessel ist oeffentlich (Schluesselhistorie der Instanz, key_id "
                f"{seal.get('key_id')}); ohne ihn ist Urheberschaft nicht pruefbar.",
            )
        )
    else:
        try:
            verify_seal_signature(seal, check_key)
            source = (
                "mit dem VORGELEGTEN oeffentlichen Schluessel"
                if public_key_hex
                else "mit dem Schluessel AUS DEM PAKET (Herkunft nicht unabhaengig belegt; "
                "gegen die veroeffentlichte Schluesselhistorie halten oder --public-key vorlegen)"
            )
            checks.append(
                _check(
                    "3. Signatur (Ed25519)",
                    BESTANDEN,
                    f"Ed25519-Signatur {source} verifiziert (key_id {seal.get('key_id')})",
                )
            )
        except PruefungGescheitert as e:
            checks.append(_check("3. Signatur (Ed25519)", NICHT_BESTANDEN, str(e)))
    if public_key_hex and package_key:
        if str(package_key).lower() == public_key_hex.lower():
            checks.append(
                _check(
                    "3b. Paket-Schluessel gegen vorgelegten Schluessel",
                    BESTANDEN,
                    "der im Paket genannte oeffentliche Schluessel ist identisch mit dem vorgelegten",
                )
            )
        else:
            checks.append(
                _check(
                    "3b. Paket-Schluessel gegen vorgelegten Schluessel",
                    NICHT_BESTANDEN,
                    "das Paket nennt einen ANDEREN oeffentlichen Schluessel als den vorgelegten",
                )
            )
    else:
        checks.append(
            _check(
                "3b. Paket-Schluessel gegen vorgelegten Schluessel",
                UEBERSPRUNGEN,
                "nur pruefbar, wenn beides vorliegt (Schluessel im Paket und --public-key)",
            )
        )

    # Schritt 3c: der Schluessel gegen die VEROEFFENTLICHTE Historie (S6-F4,
    # #150).
    #
    # Schritt 3 stellt fest, DASS eine Signatur zu einem Schluessel passt -
    # nicht, WELCHER Schluessel das ist. Wer den Schluessel dem Paket
    # entnimmt (und der Erzeuger tat in seiner Selbstpruefung genau das),
    # prueft das Paket gegen sich selbst: ein Angreifer mit eigenem
    # Schluesselpaar und einem echten Token auf sein eigenes Siegel besteht
    # jeden dieser Schritte. Das ist A7a.
    #
    # Erst die Aufloesung ueber die key_id in einer Quelle, die NICHT im
    # Paket liegt, bindet die Urheberschaft an uns. Die Historie ist genau
    # diese Quelle; der Abgleich geht ueber die key_id, nie ueber die
    # Position im Eintragsfeld (seit #142 stehen mehrere Eintraege im
    # ba--Raum).
    lbl_hist = "3c. Schluessel gegen die veroeffentlichte Schluesselhistorie"
    schluessel_gedeckt = False
    if key_history is None:
        checks.append(
            _check(
                lbl_hist,
                UEBERSPRUNGEN,
                "keine Schluesselhistorie vorgelegt (--key-history). Damit ist nur geprueft, "
                "DASS die Signatur zu einem Schluessel passt, nicht WELCHEM: ein Paket, dessen "
                "Schluessel aus dem Paket selbst stammt, bezeugt in diesem Punkt nur sich "
                "selbst. Die Historien liegen oeffentlich im Pruef-Repository "
                "https://github.com/esoxconsult/phm-verifier unter keys/ "
                "(seal_key_history.json fuer ba-, werk_key_history.json fuer wk-, "
                "archiv_manifest_key_history.json fuer am-).",
            )
        )
    elif check_key is None:
        checks.append(
            _check(
                lbl_hist,
                UEBERSPRUNGEN,
                "kein oeffentlicher Schluessel vorhanden, der gegen die Historie zu halten waere.",
            )
        )
    else:
        kid = seal.get("key_id")
        eintrag = key_history.get(kid)
        if eintrag is None:
            checks.append(
                _check(
                    lbl_hist,
                    NICHT_BESTANDEN,
                    f"key_id {kid!r} steht NICHT in der vorgelegten Schluesselhistorie. Das "
                    "Siegel stammt damit nicht von einem Schluessel, den wir veroeffentlicht "
                    "haben - wer mit eigenem Paar siegelt, faellt genau hier auf (A7a).",
                )
            )
        elif eintrag["public_key"].lower() != check_key.lower():
            checks.append(
                _check(
                    lbl_hist,
                    NICHT_BESTANDEN,
                    f"key_id {kid} fuehrt in der Historie den Schluessel "
                    f"{eintrag['public_key'][:16]}..., geprueft wurde gegen "
                    f"{check_key[:16]}... - dieselbe Kennung fuer ein anderes Schluesselpaar",
                )
            )
        else:
            grund = _im_gueltigkeitsfenster(eintrag, seal.get("sealed_at"))
            if grund:
                checks.append(
                    _check(
                        lbl_hist,
                        NICHT_BESTANDEN,
                        f"das Siegel vom {seal.get('sealed_at')} ist mit {kid} signiert, aber "
                        f"dieser Schluessel {grund}",
                    )
                )
            else:
                schluessel_gedeckt = True
                begruendung = (
                    f"key_id {kid} ueber die veroeffentlichte Historie aufgeloest; der dort "
                    "gefuehrte oeffentliche Schluessel ist derselbe, gegen den Schritt 3 "
                    f"geprueft hat, und das Siegeldatum {seal.get('sealed_at')} liegt im "
                    "Gueltigkeitsfenster. Die Urheberschaft ist damit an eine Quelle "
                    "AUSSERHALB des Pakets gebunden."
                )
                if eintrag.get("note"):
                    # Der Vermerk der Historie gehoert in den Befund: beim
                    # Demo-Schluessel steht dort, dass der geheime Seed offen
                    # im Repo liegt. Ein Pruefer, der das nicht liest, haelt
                    # eine Uebungsakte fuer eine echte.
                    begruendung += f" Vermerk der Historie: {eintrag['note']}"
                checks.append(_check(lbl_hist, BESTANDEN, begruendung))

    # Schritt 1b: Auslieferungsliste (S6/A5, #116). Der schaerfste Befund des
    # roten Teams brauchte keinen Schluessel: versiegelt war die Nutzlast,
    # gelesen wird die Datei daneben. Diese Pruefung haelt jede gelieferte
    # Datei gegen die mitversiegelte Liste - veraendert, fehlend und
    # zusaetzlich sind drei verschiedene Befunde, und alle drei sind Fehler.
    lieferliste = (envelope or {}).get("auslieferung") if isinstance(envelope, dict) else None
    geliefert = package.get("_geliefert")
    lbl_liefer = "1b. Auslieferung: gelieferte Dateien gegen die versiegelte Liste"

    # Vorab: welche Pfade BEHAUPTET die nachgelagerte Liste? Nur die Namen,
    # noch kein Urteil - das faellt in Schritt 1c. Schritt 1b braucht sie, um
    # nicht ueber Dateien zu urteilen, die ein anderer Schritt nimmt. Genau so
    # herum ist die Ausnahme zulaessig: nicht "traegt seine Pruefbarkeit
    # selbst", sondern "eine ANDERE Pruefung nimmt den Gegenstand".
    nachtrag = package.get("_nachtrag")
    nachtrag_pfade: set = set()
    if isinstance(nachtrag, dict) and isinstance(nachtrag.get("eintraege"), list):
        for e in nachtrag["eintraege"]:
            if isinstance(e, dict) and isinstance(e.get("pfad"), str):
                nachtrag_pfade.add(e["pfad"])
    if package.get("_nachtrag_pfad"):
        # Der Nachtrag fuehrt sich nie selbst - er IST der Gegenstand von 1c.
        nachtrag_pfade.add(str(package["_nachtrag_pfad"]))
    versiegelte_pfade: set = set()
    # Was geliefert wird und von KEINEM Schritt gedeckt ist (S2a/S2b,
    # 03.10.2026). Nur ohne versiegelte Liste: mit Liste meldet 1b jede
    # Datei ausserhalb der Liste als Fehler. Frueher stand hier pauschal
    # "z. B. AKTE.md", auch im Werk-Paket, das keine AKTE.md hat (S11); jetzt
    # stehen die tatsaechlichen Namen da, im Befund und im Gesamturteil.
    # Nicht mitgenannt: die Paketdatei (Gegenstand der Pruefung), die
    # Inhaltsdatei (Schritt 1a), was die nachgelagerte Liste fuehrt (1c) und
    # der Archiv-Nachweis (1d prueft ihn und seine Bindung an dieses Paket).
    ungedeckt: List[str] = []
    if lieferliste is None and geliefert:
        ungedeckt = sorted(
            (p for p in geliefert
             if p not in (package.get("_paketdatei"), package.get("_archiv_nachweis_pfad"))
             and p not in inhalt_pfade
             and p not in nachtrag_pfade),
            key=lambda p: (p.count("/"), p))
    if lieferliste is None:
        if geliefert:
            text = (
                "Der Umschlag benennt keine Auslieferungsliste. "
                + (f"Die Inhaltsdatei ({', '.join(inhalt_pfade)}) haelt Schritt 1a gegen die "
                   "versiegelte Nutzlast. " if inhalt_pfade else "")
                + "Die uebrigen gelieferten Dateien sind NICHT vom Siegel gedeckt und werden "
                "von keinem Schritt geprueft: wer sie aendert und die BagIt-Manifeste "
                "nachrechnet, faellt nicht auf (rotes Team 01, A5). Betroffen: "
                + (_gekuerzt(ungedeckt, 16) if ungedeckt else "keine weitere Datei") + "."
            )
        else:
            text = (
                "Der Umschlag benennt keine Auslieferungsliste, und die Eingabe ist die nackte "
                "Paketdatei; Dateien neben dem Paket ausser der Inhaltsdatei (Schritt 1a) sind "
                "vom Siegel nicht gedeckt."
            )
        checks.append(_check(lbl_liefer, UEBERSPRUNGEN, text))
    elif not isinstance(lieferliste, list):
        # S6-F5 (#151): die Formpruefung INNERHALB der Liste war sauber, der
        # Fall "die Liste ist gar keine Liste" lag davor. enumerate(5) wirft
        # einen TypeError, und die CLI faengt nur PaketFehler - der Empfaenger
        # sah einen Traceback statt eines Befundes. Ein Pruefwerkzeug, das an
        # manipulierter Eingabe abstuerzt, gibt dem Faelscher die Wahl
        # zwischen "faellt auf" und "sieht nach unserem Fehler aus".
        #
        # Der Befund haengt bewusst NICHT daran, ob Dateien geliefert wurden:
        # ein kaputtes Feld im versiegelten Umschlag ist ein Mangel des
        # vorgelegten Dokuments, auch wenn die nackte Paketdatei vorliegt.
        checks.append(
            _check(
                lbl_liefer,
                NICHT_BESTANDEN,
                f"auslieferung: Liste erwartet, gelesen {type(lieferliste).__name__}. "
                "Das Feld steht im versiegelten Umschlag; in dieser Form benennt es keine "
                "einzige Datei und deckt daher auch keine.",
            )
        )
    elif not geliefert:
        checks.append(
            _check(
                lbl_liefer,
                UEBERSPRUNGEN,
                "Eingabe ist die nackte Paketdatei; es liegen keine ausgelieferten Dateien vor, "
                "die gegen die Liste zu halten waeren.",
            )
        )
    else:
        # Die Liste kommt roh aus dem Umschlag. Ein fehlendes Feld gab hier
        # frueher einen Traceback, weil die CLI nur PaketFehler faengt - ein
        # Pruefwerkzeug, das an kaputter Eingabe abstuerzt, liefert kein
        # Urteil. Und doppelte Pfade gewannen still ("letzter gewinnt"), statt
        # ein Fehler zu sein: zwei Zeilen fuer dieselbe Datei sind ein
        # Widerspruch, keine Praezisierung.
        erwartet: Dict[str, str] = {}
        form_befunde: List[str] = []
        for i, z in enumerate(lieferliste):
            if not isinstance(z, dict):
                form_befunde.append(f"auslieferung[{i}]: Objekt erwartet, gelesen {type(z).__name__}")
                continue
            pfad, soll = z.get("pfad"), z.get("sha256")
            if not isinstance(pfad, str) or not pfad:
                form_befunde.append(f"auslieferung[{i}]: Feld 'pfad' fehlt oder ist kein Text")
                continue
            if not isinstance(soll, str) or not _SHA256_RE.match(soll):
                form_befunde.append(
                    f"auslieferung[{i}] ({pfad}): Feld 'sha256' fehlt oder ist keine "
                    "64-stellige Hex-Prueffsumme"
                )
                continue
            if pfad in erwartet:
                form_befunde.append(
                    f"auslieferung: Pfad {pfad} kommt doppelt vor - zwei Zeilen fuer dieselbe "
                    "Datei sind ein Widerspruch, nicht die eine gueltige"
                )
                continue
            erwartet[pfad] = soll
        if form_befunde:
            # Kaputte Liste: ein Befund, kein Absturz - und kein zweites Urteil
            # ueber dieselbe Liste.
            checks.append(_check(lbl_liefer, NICHT_BESTANDEN, "; ".join(form_befunde)))
        else:
            versiegelte_pfade = set(erwartet)
            befunde: List[str] = []
            for pfad, soll in sorted(erwartet.items()):
                ist = geliefert.get(pfad)
                if ist is None:
                    befunde.append(f"{pfad}: in der versiegelten Liste genannt, aber nicht geliefert")
                elif ist != soll:
                    befunde.append(f"{pfad}: veraendert (Liste {soll[:16]}..., geliefert {ist[:16]}...)")
            # Zusaetzliche Dateien: was erst DURCH das Versiegeln entsteht,
            # kann sich nicht selbst in der versiegelten Liste fuehren. Das
            # ist das Siegelpaket - Gegenstand der Pruefung selbst - und
            # alles, was die nachgelagerte Liste fuehrt; darueber urteilt
            # Schritt 1d.
            #
            # Bis S6-F1 (#144) stand hier stattdessen `pfad in
            # NACH_DEM_SIEGELN`, eine unbedingte Ausnahme fuer einen festen
            # Dateinamen. Wer Dateizugriff hatte, konnte unter diesem Namen
            # ablegen, was er wollte: 1b blieb bestanden. Jetzt haengt die
            # Ausnahme daran, dass eine SIGNIERTE Liste die Datei fuehrt -
            # fehlt sie, faellt die Datei hier auf.
            for pfad in sorted(geliefert):
                if (pfad in erwartet
                        or pfad == package.get("_paketdatei")
                        or pfad in nachtrag_pfade):
                    continue
                befunde.append(f"{pfad}: geliefert, steht aber nicht in der versiegelten Liste")
            if befunde:
                checks.append(_check(lbl_liefer, NICHT_BESTANDEN, "; ".join(befunde)))
            else:
                checks.append(
                    _check(
                        lbl_liefer,
                        BESTANDEN,
                        f"{len(erwartet)} gelieferte Datei(en) unter data/ gegen die "
                        "mitversiegelte Liste gehalten: keine veraendert, keine fehlt, keine "
                        "zusaetzliche. Die Liste haengt am Umschlag und damit an der Signatur. "
                        "Geprueft wird ausschliesslich die Nutzlast unter data/; die "
                        "BagIt-Tag-Dateien daneben (bag-info.txt mit PHM-Stichtag und "
                        "PHM-Erstellt-Am, bagit.txt, die Manifeste) deckt DIESE Liste nicht - "
                        "die inhaltlichen Angaben aus bag-info.txt haelt seit S6-F3 (#149) "
                        "Schritt 0b gegen den versiegelten Umschlag. Ebenso nicht von dieser "
                        "Liste gedeckt, weil erst nach dem Siegeln entstanden: das Siegelpaket "
                        "selbst und archiv_nachweis.json (den fuehrt die nachgelagerte Liste aus Schritt 1c, inhaltlich geprueft wird er in Schritt 1d).",
                    )
                )

    # Schritt 1c: die NACHGELAGERTE Auslieferungsliste (S6-F1, #144).
    #
    # Werners Entscheidung zum Folgepunkt: eine zweite Liste fuer alles, was
    # nach dem Siegeln entsteht. Sie kann vom Siegel nicht gedeckt sein - sie
    # entsteht danach, das ist keine Schwaeche, sondern ihre Definition. Was
    # sie leistet, ist kleiner und muss genau so benannt werden: die Bindung
    # der nachgelagerten Dateien an den ERZEUGER (Signatur mit dem
    # Siegel-Schluessel), an DIESES Paket (Prueffsumme des ausgelieferten
    # Siegelpakets) und an einen behaupteten Zeitpunkt.
    #
    # Sie ersetzt die unbedingte Ausnahme in 1b. Vorher galt "der Nachweis
    # traegt seine Pruefbarkeit selbst" - eine Eigenschaft des Gegenstands,
    # keine ausgefuehrte Pruefhandlung.
    lbl_nachtrag = "1c. Nachgelagerte Liste: die nach dem Siegeln entstandenen Dateien"
    nachtrag_pfad = package.get("_nachtrag_pfad")
    nachtrag_fehler = package.get("_nachtrag_fehler")
    if not geliefert:
        checks.append(
            _check(
                lbl_nachtrag,
                UEBERSPRUNGEN,
                "Eingabe ist die nackte Paketdatei; es liegen keine ausgelieferten Dateien vor, "
                "die eine nachgelagerte Liste fuehren koennte.",
            )
        )
    elif nachtrag_pfad is None:
        checks.append(
            _check(
                lbl_nachtrag,
                UEBERSPRUNGEN,
                "keine nachgelagerte Liste (nachtrag.json) mitgeliefert. Das Paket behauptet "
                "damit keine nach dem Siegeln entstandenen Dateien - und es bekommt fuer "
                "solche Dateien auch keine Ausnahme: was geliefert wird und in keiner Liste "
                "steht, meldet Schritt 1b als zusaetzlich.",
            )
        )
    elif nachtrag_fehler:
        checks.append(_check(lbl_nachtrag, NICHT_BESTANDEN, f"{nachtrag_pfad}: {nachtrag_fehler}"))
    else:
        befunde_nt: List[str] = []
        eintraege: List[Dict[str, str]] = []
        try:
            nachricht = nachtrag_signed_bytes(nachtrag)
            ist_summe = nachtrag_eintraege_pruefsumme(nachtrag.get("eintraege"))
            eintraege = [e for e in nachtrag["eintraege"] if isinstance(e, dict)]
            if ist_summe != nachtrag.get("eintraege_pruefsumme"):
                befunde_nt.append(
                    "die Eintragsliste passt nicht zu der Prueffsumme, die mitsigniert wurde "
                    f"(nachgerechnet {ist_summe[:16]}..., signiert "
                    f"{str(nachtrag.get('eintraege_pruefsumme'))[:16]}...) - die Liste wurde "
                    "nach dem Signieren veraendert"
                )
            nt_key = nachtrag.get("public_key")
            pruef_key = check_key or (str(nt_key) if nt_key else None)
            if pruef_key is None:
                befunde_nt.append("kein oeffentlicher Schluessel, gegen den die Signatur zu pruefen waere")
            else:
                if nt_key and check_key and str(nt_key).lower() != check_key.lower():
                    befunde_nt.append(
                        "die nachgelagerte Liste nennt einen ANDEREN oeffentlichen Schluessel "
                        "als das Siegel - sie stammt dann nicht vom Erzeuger dieses Pakets"
                    )
                try:
                    sig = bytes.fromhex(str(nachtrag.get("signature") or ""))
                except ValueError:
                    sig = b""
                if not sig or not ed25519_verify(bytes.fromhex(pruef_key), nachricht, sig):
                    befunde_nt.append(
                        "die Signatur der nachgelagerten Liste ist ungueltig - ohne sie ist die "
                        "Liste eine Behauptung ohne Urheber, und jeder mit Dateizugriff kann sie "
                        "schreiben"
                    )
            if nachtrag.get("key_id") != seal.get("key_id"):
                befunde_nt.append(
                    f"die Liste ist mit key_id {nachtrag.get('key_id')!r} signiert, das Siegel "
                    f"mit {seal.get('key_id')!r}"
                )
            soll_paket = geliefert.get(package.get("_paketdatei"))
            if soll_paket and nachtrag.get("siegel_paket_sha256") != soll_paket:
                befunde_nt.append(
                    "die Liste gehoert zu einem ANDEREN Siegelpaket: sie nennt "
                    f"{str(nachtrag.get('siegel_paket_sha256'))[:16]}..., geliefert wurde "
                    f"{soll_paket[:16]}... Eine gueltige Liste aus einer fremden Auslieferung "
                    "belegt fuer diese hier nichts"
                )
        except PaketFehler as e:
            befunde_nt.append(str(e))

        for e in eintraege:
            pfad, soll = e.get("pfad"), e.get("sha256")
            if not isinstance(pfad, str) or not isinstance(soll, str):
                continue
            if pfad in versiegelte_pfade:
                befunde_nt.append(
                    f"{pfad}: steht bereits in der VERSIEGELTEN Liste. Eine nachgelagerte "
                    "Angabe darf eine versiegelte nicht ueberschreiben - sonst waere die "
                    "schwaechere Liste die letzte Instanz"
                )
                continue
            ist = geliefert.get(pfad)
            if ist is None:
                befunde_nt.append(f"{pfad}: in der nachgelagerten Liste genannt, aber nicht geliefert")
            elif ist != soll:
                befunde_nt.append(
                    f"{pfad}: veraendert (Liste {soll[:16]}..., geliefert {ist[:16]}...)"
                )

        if befunde_nt:
            checks.append(_check(lbl_nachtrag, NICHT_BESTANDEN, "; ".join(befunde_nt)))
        else:
            checks.append(
                _check(
                    lbl_nachtrag,
                    BESTANDEN,
                    f"{len(eintraege)} nach dem Siegeln entstandene Datei(en) gegen die "
                    f"signierte Liste {nachtrag_pfad} gehalten: keine veraendert, keine fehlt. "
                    "GEDECKT ist damit die Bindung an den Erzeuger (Signatur mit dem "
                    f"Siegel-Schluessel {nachtrag.get('key_id')}) und an genau dieses "
                    "Siegelpaket. NICHT gedeckt - und das kann sie nicht sein, weil sie nach "
                    f"dem Siegeln entsteht - ist sie vom Siegel selbst; {nachtrag.get('erstellt_am')} "
                    "ist die Zeitangabe des Erzeugers und durch keinen Dritten bezeugt. Wer "
                    "den geheimen Schluessel hat, kann diese Liste jederzeit neu schreiben.",
                )
            )

    # Schritt 1d: der Archiv-Zugehoerigkeitsnachweis (Folgepunkt zur
    # Nachpruefung 02.08.2026).
    #
    # Schritt 1b nimmt data/archiv_nachweis.json unbedingt aus, weil die Datei
    # erst nach dem Siegeln entsteht und deshalb nicht in der mitversiegelten
    # Liste stehen kann. Die Begruendung daneben lautete, der Nachweis trage
    # seine Pruefbarkeit selbst. Das stimmte nur fuer den getrennten
    # Eingabetyp: verify_archive_proof ist ein eigener Aufruf, den der
    # Paketpfad nie erreicht hat. Wer Dateizugriff hatte, konnte eine fremde
    # oder erfundene Datei unter diesem Namen ablegen - 1b blieb bestanden,
    # das Gesamturteil blieb bestanden. Das ist A5c, der Angriff, der nur
    # Dateizugriff braucht, fuer genau einen Dateinamen wieder offen.
    #
    # Geprueft wird deshalb beides, und beides ist noetig:
    #   - der Nachweis fuer sich (dieselbe Rechnung wie im getrennten Pfad),
    #   - und dass er von DIESEM Paket handelt. Ein in sich gueltiger Nachweis
    #     ueber ein fremdes Dokument ist kein Nachweis ueber dieses; die
    #     Bindung ist die Prueffsumme des Siegelpakets in der Index-Zeile,
    #     denn genau ueber dessen Bytes archiviert der Erzeuger
    #     (belegakte_build.verankere_im_archiv).
    lbl_nw = "1d. Archiv-Zugehoerigkeitsnachweis: geprueft und an dieses Paket gebunden"
    nw_pfad = package.get("_archiv_nachweis_pfad")
    nw_fehler = package.get("_archiv_nachweis_fehler")
    nachweis = package.get("_archiv_nachweis")
    if not geliefert:
        checks.append(
            _check(
                lbl_nw,
                UEBERSPRUNGEN,
                "Eingabe ist die nackte Paketdatei; es liegen keine ausgelieferten Dateien "
                "vor, unter denen ein Nachweis zu pruefen waere.",
            )
        )
    elif nw_pfad is None:
        checks.append(
            _check(
                lbl_nw,
                UEBERSPRUNGEN,
                "kein archiv_nachweis.json mitgeliefert. Das Paket behauptet damit keine "
                "Archiv-Zugehoerigkeit, und es wird auch keine geprueft. Ein Paket OHNE "
                "Nachweis ist kein Fehler; ein Paket mit einem falschen waere einer.",
            )
        )
    elif nw_fehler:
        checks.append(_check(lbl_nw, NICHT_BESTANDEN, f"{nw_pfad}: {nw_fehler}"))
    else:
        befunde_nw: List[str] = []
        teil = verify_archive_proof(
            nachweis,
            public_key_hex=archiv_public_key_hex,
            trusted_cert_der=trusted_cert_der,
        )
        gescheitert = [
            c["pruefung"] for c in teil["checks"] if c["ergebnis"] == NICHT_BESTANDEN
        ]
        if gescheitert:
            befunde_nw.append(
                "der Nachweis traegt schon fuer sich nicht: " + "; ".join(gescheitert)
            )

        # Bindung an dieses Paket.
        soll_paket = geliefert.get(package.get("_paketdatei"))
        try:
            zeile_obj = json.loads(nachweis["index_zeile"])
        except ValueError:
            zeile_obj = None
        ist_dok = None
        if isinstance(zeile_obj, dict):
            pruefsummen = zeile_obj.get("pruefsummen")
            if isinstance(pruefsummen, dict):
                ist_dok = pruefsummen.get("sha256")
        if not isinstance(ist_dok, str) or not _SHA256_RE.match(ist_dok):
            befunde_nw.append(
                "die Index-Zeile des Nachweises fuehrt keine sha256-Prueffsumme unter "
                "'pruefsummen' - dann ist nicht feststellbar, WELCHES Dokument sie meint"
            )
        elif soll_paket is None:
            befunde_nw.append(
                "die Prueffsumme des Siegelpakets liegt nicht vor - die Bindung des "
                "Nachweises an dieses Paket ist nicht feststellbar"
            )
        elif ist_dok != soll_paket:
            befunde_nw.append(
                "der Nachweis gehoert zu einem ANDEREN Dokument: seine Index-Zeile nennt "
                f"{ist_dok}, das gelieferte {package.get('_paketdatei')} hat "
                f"{soll_paket}. Ein Nachweis ueber ein fremdes Dokument belegt fuer "
                "dieses hier nichts"
            )

        if befunde_nw:
            checks.append(_check(lbl_nw, NICHT_BESTANDEN, "; ".join(befunde_nw)))
        else:
            # Woher der Manifest-Schluessel kam, gehoert in den Befund. Ohne
            # vorgelegten Schluessel prueft A3 gegen den Schluessel IM
            # Nachweis, und dann traegt dieser Schritt genau so weit wie der
            # getrennte Pfad: er schliesst die untergeschobene und die
            # fremde Datei aus, nicht die von Grund auf erfundene Kette.
            herkunft = (
                "gegen den VORGELEGTEN Archiv-Manifest-Schluessel geprueft"
                if archiv_public_key_hex
                else "gegen den Schluessel IM Nachweis geprueft - wer den Nachweis erfunden "
                "hat, hat auch diesen Schluessel erfunden; mit --archiv-public-key laesst "
                "sich das ausschliessen"
            )
            checks.append(
                _check(
                    lbl_nw,
                    BESTANDEN,
                    f"{nw_pfad} vorhanden, {len(teil['checks'])} Nachweis-Schritte gefahren "
                    f"({herkunft}). Die Index-Zeile nennt die Prueffsumme des gelieferten "
                    f"{package.get('_paketdatei')} ({ist_dok[:16]}...), der Nachweis handelt "
                    "also von DIESEM Paket. Eine untergeschobene oder zu einem fremden "
                    "Dokument gehoerende Datei faellt damit hier auf, statt von Schritt 1b "
                    "ungeprueft durchgelassen zu werden.",
                )
            )

    # Schritt 4: Zeitstempel-Token. Seit der Entscheidung #28 traegt ein
    # Siegel mehrere Anker (qualifizierter + freier Dienst, dazu
    # Kettenkopf-Erneuerungen); JEDER wird vollstaendig geprueft. Bei genau
    # einem Anker bleiben die Labels "4."/"4b.", sonst "4.<i>"/"4.<i>b".
    anchors = package.get("anchors") or []
    if not isinstance(anchors, list):
        anchors = []
    if not anchors:
        # S6-F2 (#148), zweite Luecke: der Zeitbefund entstand ausschliesslich
        # im BESTANDEN-Zweig eines vorhandenen Tokens. Ohne Anker schwieg das
        # Ergebnis zu sealed_at - und ein Schweigen liest sich wie ein Befund
        # ohne Beanstandung. A6a ist genau dieser Fall und der billigere
        # Angriff: er braucht kein Token, nur den Schluessel.
        ohne_anker = (
            "Paket enthaelt keinen Anker (Siegel noch nicht extern verankert, anchor_pending). "
            "Ohne Anker gibt es keine Fremdbeglaubigung des Zeitpunkts."
        )
        behauptet = str(seal.get("sealed_at") or "")
        if behauptet:
            ohne_anker += (
                f" Ueber sealed_at {behauptet} ist damit KEINE Aussage getroffen: die Angabe "
                "stammt vom Aufzeichnenden und ist durch nichts in diesem Paket gedeckt. Wer "
                "den geheimen Schluessel hat, kann sie frei waehlen und neu siegeln; eine "
                "Rueckdatierung ist an diesem Paket weder feststellbar noch ausgeschlossen."
            )
        checks.append(_check("4. Zeitstempel-Token (RFC 3161)", UEBERSPRUNGEN, ohne_anker))
        checks.append(
            _check("4b. TSA-Zertifikat gegen Vertrauenszertifikat", UEBERSPRUNGEN, "kein Anker im Paket")
        )
    for idx, anchor in enumerate(anchors, start=1):
        if len(anchors) == 1:
            lbl_token = "4. Zeitstempel-Token (RFC 3161)"
            lbl_cert = "4b. TSA-Zertifikat gegen Vertrauenszertifikat"
        else:
            wer = anchor.get("tsa_id") or "?"
            zweck = anchor.get("zweck")
            zusatz = f", {wer}" + (f", {zweck}" if zweck and zweck != "direkt" else "")
            lbl_token = f"4.{idx} Zeitstempel-Token (RFC 3161{zusatz})"
            lbl_cert = f"4.{idx}b TSA-Zertifikat gegen Vertrauenszertifikat"
        try:
            if recomputed_hash is None:
                raise PruefungGescheitert("Siegel nicht nachrechenbar (Schritt 2), Anker nicht zuordenbar")
            try:
                token_der = base64.b64decode(str(anchor.get("token_b64", "")), validate=True)
            except (ValueError, binascii.Error):
                raise PruefungGescheitert("anchor.token_b64: keine gueltige Base64-Kodierung")
            if not token_der:
                raise PruefungGescheitert("anchor.token_b64: leer")
            claimed_sha = anchor.get("token_sha256")
            if claimed_sha is not None and claimed_sha != hashlib.sha256(token_der).hexdigest():
                raise PruefungGescheitert("anchor.token_sha256 passt nicht zu den Token-Bytes")
            info = verify_timestamp_token(token_der, trusted_cert_der)
            if info["hash_algo_oid"] != OID_SHA256:
                raise PruefungGescheitert("messageImprint: Algorithmus ist nicht SHA-256")
            if info["hashed_message"] != recomputed_hash:
                raise PruefungGescheitert(
                    "das Token bezeugt einen anderen Hash als den nachgerechneten seal_hash "
                    f"(Token {info['hashed_message']}, Siegel {recomputed_hash})"
                )
            # Die BEHAUPTETEN Anker-Angaben gegen das Token halten (Befund der
            # Gate-A-Probe 30.07.2026, Fall D): ohne diesen Abgleich konnte die
            # Zeitangabe neben dem Token frei umgeschrieben werden, ohne dass
            # eine Pruefung anschlug - das Token blieb ja gueltig. Massgeblich
            # ist immer das Token; die Angabe daneben ist nur eine Behauptung.
            behauptet_zeit = anchor.get("gen_time")
            if behauptet_zeit is not None and str(behauptet_zeit) != info["gen_time"]:
                raise PruefungGescheitert(
                    "die im Paket behauptete Anker-Zeit weicht vom Zeitstempel-Token ab "
                    f"(behauptet {behauptet_zeit}, Token {info['gen_time']})"
                )
            behauptet_algo = anchor.get("hash_algo")
            if behauptet_algo is not None and str(behauptet_algo).lower() != "sha256":
                raise PruefungGescheitert(
                    f"anchor.hash_algo behauptet '{behauptet_algo}', das Token nutzt SHA-256"
                )
            detail = (
                f"messageImprint = nachgerechneter seal_hash; TSA-Signatur "
                f"({info['signature_scheme']}, OID {info['signature_algo_oid']}) ueber den signierten "
                f"Attributen verifiziert; messageDigest und contentType geprueft"
                + ("; ESSCertID geprueft" if info["ess_cert_id_checked"] else "")
                + f"; genTime {info['gen_time']}, Serial 0x{info['serial']:x}, "
                f"Signer-Zertifikat SHA-256 {info['signer_cert_sha256']}"
            )
            # S6/A6 (#116): die bewiesene Zeit benennen und die behauptete als
            # das ausweisen, was sie ist. Der Angriff A6b hat nicht die
            # Reihenfolge verletzt, sondern ausgenutzt, dass der Verifier eine
            # BEHAUPTUNG (sealed_at) wie einen Beweis behandelt hat.
            detail += f". Existenz bewiesen ab {info['gen_time']} (Zeitstempel eines Dritten)"
            sealed_at = str(seal.get("sealed_at") or "")
            if sealed_at:
                detail += (
                    f"; sealed_at {sealed_at} ist die Angabe des Aufzeichnenden und durch dieses "
                    "Token nicht gedeckt"
                )
                abstand = _zeitabstand_stunden(sealed_at, info["gen_time"])
                if abstand is None:
                    detail += " (Abstand nicht berechenbar)"
                elif abstand < -(TOLERANZ_UHRENVORLAUF_SEKUNDEN / 3600.0):
                    # S6-F2 (#148): lief bisher kommentarlos durch, weil nur
                    # der positive Abstand abgefragt wurde. Wer diesen Zustand
                    # sieht, sieht eine Faelschung oder einen kaputten
                    # Erzeuger - und bekam bislang nichts angezeigt.
                    raise PruefungGescheitert(
                        f"sealed_at {sealed_at} liegt {-abstand:.0f} h NACH der bewiesenen Zeit "
                        f"{info['gen_time']}. Das ist unmoeglich: das Token bezeugt einen Hash, "
                        "der das sealed_at bereits enthaelt, das Siegel muss also vorher "
                        "existiert haben. Entweder wurde die Angabe nachtraeglich veraendert "
                        "oder der Erzeuger ist defekt; ein legitimer Fall dafuer existiert "
                        f"nicht (Uhrenvorlauf bis {TOLERANZ_UHRENVORLAUF_SEKUNDEN} s toleriert)"
                    )
                elif abstand > SCHWELLE_ANKER_ABSTAND_STUNDEN:
                    detail += (
                        f". BEFUND: die Angabe liegt {abstand:.0f} h vor der bewiesenen Zeit "
                        f"(Schwelle {SCHWELLE_ANKER_ABSTAND_STUNDEN} h). Das Token bezeugt den "
                        "frueheren Zeitpunkt nicht; wer ihn braucht, braucht einen Anker von damals"
                    )
            checks.append(_check(lbl_token, BESTANDEN, detail))
            if info["trusted_cert_match"] is None:
                checks.append(
                    _check(
                        lbl_cert,
                        UEBERSPRUNGEN,
                        "kein Vertrauenszertifikat vorgelegt (--tsa-cert). Die Signatur wurde gegen das "
                        "IM TOKEN mitgefuehrte Zertifikat geprueft; ob dieses Zertifikat der erwarteten "
                        "TSA gehoert, muss der Pruefer selbst feststellen (docs/VERIFIKATION.md).",
                    )
                )
            elif info["trusted_cert_match"]:
                checks.append(
                    _check(
                        lbl_cert,
                        BESTANDEN,
                        "das Signer-Zertifikat im Token ist byte-identisch mit einem vorgelegten "
                        f"Vertrauenszertifikat (SHA-256 {info['signer_cert_sha256']})",
                    )
                )
            else:
                checks.append(
                    _check(
                        lbl_cert,
                        NICHT_BESTANDEN,
                        "das Signer-Zertifikat im Token ist KEINES der vorgelegten Vertrauenszertifikate "
                        f"(Token-Zertifikat SHA-256 {info['signer_cert_sha256']})",
                    )
                )
        except PruefungGescheitert as e:
            checks.append(_check(lbl_token, NICHT_BESTANDEN, str(e)))
            checks.append(_check(lbl_cert, UEBERSPRUNGEN, "Token-Pruefung gescheitert"))

    # Schritt 5: Baum-Fortschreibung
    tree = package.get("tree")
    tree_root: Optional[str] = None
    # Ein LEERES Baum-Feld ist etwas anderes als ein fehlendes (Befund der
    # Gate-A-Probe 30.07.2026, Fall C): wer die Blaetter aus einem Paket
    # entfernt, das einen Baum mitliefert, bekam bisher ein "uebersprungen"
    # und damit ein bestandenes Gesamturteil. Behauptet das Paket an anderer
    # Stelle einen Baum (membership.tree_size >= 1), ist ein leerer Baum ein
    # Widerspruch und damit ein Fehlschlag, kein uebersprungener Schritt.
    _m = package.get("membership") or {}
    try:
        _behauptete_groesse = int(_m.get("tree_size"))
    except (TypeError, ValueError):
        _behauptete_groesse = 0
    if "tree" in package and not tree and _behauptete_groesse >= 1:
        checks.append(
            _check(
                "5. Baum: Blatt-Folge + Wurzel-Fortschreibung",
                NICHT_BESTANDEN,
                "das Paket fuehrt ein leeres Baum-Feld, behauptet im "
                f"Zugehoerigkeitsnachweis aber einen Baum mit {_behauptete_groesse} "
                "Blatt/Blaettern - Blaetter fehlen oder wurden entfernt.",
            )
        )
    elif not tree:
        checks.append(
            _check(
                "5. Baum: Blatt-Folge + Wurzel-Fortschreibung",
                UEBERSPRUNGEN,
                "Paket enthaelt keinen Baum-Export; das Siegel benennt seine Position "
                f"(Blatt {seal.get('leaf_index')}) und die Wurzel ueber seine Vorgaenger "
                f"({seal.get('prev_root_hash')}), Reihenfolge und Vollstaendigkeit sind ohne "
                "Baum nicht pruefbar (Zugehoerigkeit ggf. ueber Schritt 6).",
            )
        )
    else:
        try:
            if not isinstance(tree, list):
                raise PruefungGescheitert("tree: Liste erwartet")
            leaves: List[str] = []
            position = None
            for i, record in enumerate(tree):
                link_hash = recompute_seal_hash(record)
                if record.get("seal_hash") != link_hash:
                    raise PruefungGescheitert(
                        f"Blatt {i}: seal_hash passt nicht zum nachgerechneten Wert"
                    )
                if record.get("leaf_index") != str(i):
                    raise PruefungGescheitert(
                        f"Baum gebrochen an Position {i}: leaf_index {record.get('leaf_index')!r} "
                        "passt nicht zur Reihenfolge (Blatt entfernt, eingefuegt oder umsortiert)"
                    )
                expected_root = merkle_tree_root(leaves)
                if record.get("prev_root_hash") != expected_root:
                    if i == 0:
                        raise PruefungGescheitert(
                            "Blatt 0 schliesst nicht an der Wurzel des leeren Baums an "
                            "(SHA-256 ueber die leere Eingabe)"
                        )
                    raise PruefungGescheitert(
                        f"Baum gebrochen an Position {i}: prev_root_hash passt nicht zur Wurzel "
                        "ueber die Vorgaenger (Blatt entfernt, eingefuegt oder umsortiert)"
                    )
                leaves.append(link_hash)
                if recomputed_hash is not None and link_hash == recomputed_hash:
                    position = i
                    if any(record.get(f) != seal.get(f) for f in _SIGNED_FIELDS + ("signature",)):
                        raise PruefungGescheitert(
                            f"Blatt {i} traegt denselben seal_hash, aber andere Felder als das Siegel"
                        )
            if recomputed_hash is None:
                raise PruefungGescheitert("Siegel nicht nachrechenbar (Schritt 2), Position nicht bestimmbar")
            if position is None:
                raise PruefungGescheitert(
                    "das gepruefte Siegel ist KEIN Blatt des exportierten Baums"
                )
            if str(position) != str(seal.get("leaf_index")):
                raise PruefungGescheitert(
                    f"das Siegel steht an Position {position}, signiert aber leaf_index "
                    f"{seal.get('leaf_index')!r}"
                )
            tree_root = merkle_tree_root(leaves)
            checks.append(
                _check(
                    "5. Baum: Blatt-Folge + Wurzel-Fortschreibung",
                    BESTANDEN,
                    f"{len(tree)} Blaetter nachgerechnet, jede Position und jede Wurzel-"
                    f"Fortschreibung geprueft; das Siegel ist Blatt {position + 1} von {len(tree)}, "
                    f"Wurzel {tree_root}",
                )
            )
        except PruefungGescheitert as e:
            checks.append(_check("5. Baum: Blatt-Folge + Wurzel-Fortschreibung", NICHT_BESTANDEN, str(e)))

    # Schritt 6: Zugehoerigkeitsnachweis (Merkle-Pfad)
    membership = package.get("membership")
    if not membership:
        checks.append(
            _check(
                "6. Zugehoerigkeitsnachweis (Merkle-Pfad)",
                UEBERSPRUNGEN,
                "Paket enthaelt keinen Zugehoerigkeitsnachweis (membership). Mit vollem "
                "Baum-Export (Schritt 5) ist die Zugehoerigkeit dennoch belegt.",
            )
        )
    else:
        try:
            if not isinstance(membership, dict):
                raise PruefungGescheitert("membership: Objekt erwartet")
            if recomputed_hash is None:
                raise PruefungGescheitert("Siegel nicht nachrechenbar (Schritt 2), Nachweis nicht zuordenbar")
            try:
                m_size = int(membership.get("tree_size"))
                m_index = int(str(seal.get("leaf_index")))
            except (TypeError, ValueError):
                raise PruefungGescheitert("membership.tree_size/leaf_index: Zahl erwartet")
            m_root = membership.get("root_hash")
            m_path = membership.get("audit_path")
            if not isinstance(m_path, list):
                raise PruefungGescheitert("membership.audit_path: Liste erwartet")
            verify_merkle_membership(recomputed_hash, m_index, m_size, m_path, str(m_root))
            detail = (
                f"das nachgerechnete Blatt fuehrt ueber den Pfad ({len(m_path)} Knoten) zur "
                f"Wurzel {m_root} (Baum mit {m_size} Blaettern, Position {m_index})"
            )
            if tree_root is not None:
                if tree_root != m_root or m_size != len(package.get("tree") or []):
                    raise PruefungGescheitert(
                        "membership passt nicht zum exportierten Baum "
                        f"(Nachweis-Wurzel {m_root}, Baum-Wurzel {tree_root})"
                    )
                detail += "; identisch mit der Wurzel des exportierten Baums"
            else:
                detail += (
                    "; die Wurzel selbst ist in diesem Paket nicht unabhaengig belegt "
                    "(kein Baum-Export); sie gegen ein veroeffentlichtes Verzeichnis oder "
                    "einen Anker der Wurzel halten"
                )
            checks.append(_check("6. Zugehoerigkeitsnachweis (Merkle-Pfad)", BESTANDEN, detail))
        except PruefungGescheitert as e:
            checks.append(_check("6. Zugehoerigkeitsnachweis (Merkle-Pfad)", NICHT_BESTANDEN, str(e)))

    failed = [c for c in checks if c["ergebnis"] == NICHT_BESTANDEN]
    skipped = [c for c in checks if c["ergebnis"] == UEBERSPRUNGEN]
    if failed:
        verdict = (
            "NICHT BESTANDEN: mindestens eine Pruefung ist gescheitert. Die Aufzeichnung ist in "
            "diesem Paket nicht als unveraendert belegbar."
        )
    else:
        verdict = "BESTANDEN im Umfang der durchgefuehrten Pruefungen."
        if skipped:
            verdict += " Uebersprungen (nicht geprueft): " + "; ".join(c["pruefung"] for c in skipped) + "."
        verdict += (
            " Belegt sind damit Existenz und Unveraendertheit der vorgelegten Aufzeichnung"
            + (
                " sowie ihre Urheberschaft (Signatur)"
                if any(
                    c["pruefung"].startswith("3.") and c["ergebnis"] == BESTANDEN for c in checks
                )
                else ""
            )
            + (" sowie ihre Position im Siegel-Baum" if package.get("tree") or package.get("membership") else "")
            + (
                ", jeweils spaetestens seit dem Zeitpunkt im Zeitstempel-Token"
                if package.get("anchors")
                else ""
            )
            + ". NICHT belegt und nicht Gegenstand dieser Pruefung ist die inhaltliche "
            "Richtigkeit der aufgezeichneten Werte."
        )
        if ungedeckt:
            # S2a/S2b (03.10.2026): ein BESTANDEN darf nicht so klingen, als
            # gelte es fuer alles, was der Empfaenger in der Hand hat. Was
            # mitgeliefert, aber weder versiegelt noch geprueft ist, steht
            # deshalb im Urteil selbst, nicht nur im Befundtext von 1b.
            verdict += (
                " NICHT vom Siegel gedeckt und von keinem Schritt geprueft sind die "
                "mitgelieferten Dateien " + _gekuerzt(ungedeckt, 16) + "; was dort steht "
                "(etwa eine menschenlesbare Darstellung der Nutzlast), belegt dieses Urteil nicht."
            )
    # S6/A1c (#116): das Urteil ist eine STUFE, keine Ja-Nein-Aussage. Heute
    # fuehrte ein uebersprungener Schritt zum selben Urteil wie ein
    # bestandener; der Angriff A1c hat genau das ausgenutzt. Die Stufe sagt,
    # WIE WEIT das vorgelegte Paket traegt, und nennt den Schritt, der sie
    # begrenzt - begruendet statt behauptet.
    def _stand(prefix: str) -> Optional[str]:
        treffer = [c for c in checks if c["pruefung"].startswith(prefix)]
        if not treffer:
            return None
        if any(c["ergebnis"] == NICHT_BESTANDEN for c in treffer):
            return NICHT_BESTANDEN
        if any(c["ergebnis"] == BESTANDEN for c in treffer):
            return BESTANDEN
        return UEBERSPRUNGEN

    anker_ok = _stand("4.") == BESTANDEN
    # S6-F4 (#150): das Merkmal haengt jetzt an Schritt 3c, nicht mehr daran,
    # DASS irgendein Schluessel vorlag. Ein Angreifer mit eigenem
    # Schluesselpaar legte seinen eigenen Schluessel vor und erfuellte es -
    # das war A7a, und der zugehoerige Test war gruen, weil der Angriff
    # gelingt. Ohne Aufloesung ueber die veroeffentlichte Historie ist die
    # Urheberschaft nicht an uns gebunden, sondern nur an sich selbst.
    schluessel_unabhaengig = schluessel_gedeckt and _stand("3.") == BESTANDEN
    # Schritt 1b (Auslieferungsliste) und Schritt 0 (BagIt-Ablage) gehoeren in
    # die Stufe. Ohne sie bekam ein Paket OHNE versiegelte Liste 1b als
    # "uebersprungen", 3 und 4 bestanden - und damit die hoechste Stufe, mit
    # der Begruendung, der Anker sei geprueft. Der Pruefer haette die hoechste
    # Stufe ueber ein Dokument gelesen, das gefaelscht sein kann: genau das
    # Muster aus A1c, ein uebersprungener Schritt traegt ein volles Urteil.
    liefer_stand = _stand("1b.")
    liefer_ok = liefer_stand == BESTANDEN
    # Punkt 3 der Nachpruefung: der dritte Zustand war nur halb durchgezogen.
    # Bei der nackten Paketdatei ist 1b uebersprungen, weil es gar keine
    # gelieferten Dateien gibt - dasselbe "nichts nachzurechnen" wie bei
    # Schritt 0, dort aber stand "nicht anwendbar" und hier "nein". Zwei
    # Namen fuer denselben Sachverhalt. Wichtig ist die Unterscheidung zum
    # zweiten Grund fuer ein uebersprungenes 1b: fehlt die LISTE im Umschlag,
    # ist das ein Versaeumnis und bleibt "nein". Deshalb wird hier nicht der
    # Schritt-Zustand allein gelesen, sondern auch, ob ueberhaupt etwas
    # geliefert wurde.
    liefer_ergebnis = (
        "ja" if liefer_ok
        else "nicht anwendbar" if (liefer_stand == UEBERSPRUNGEN and not geliefert)
        else "nein"
    )
    # Punkt 2 der Nachpruefung: ein UEBERSPRUNGENER Schritt trug hier eine
    # erfuellte Feststellung. Das ist dasselbe Muster wie A1c. bagit_ok
    # verlangt jetzt BESTANDEN; die nackte Paketdatei (kein Verzeichnis, also
    # nichts nachzurechnen) bekommt den dritten Zustand "nicht anwendbar" -
    # weder erfuellt noch versaeumt.
    bagit_stand = _stand("0.")
    bagit_ok = bagit_stand == BESTANDEN
    bagit_ergebnis = ("ja" if bagit_ok
                      else "nicht anwendbar" if bagit_stand == UEBERSPRUNGEN
                      else "nein")
    # Buchstaben werden NICHT vergeben. docs/KRITERIENWERK.md (v0.3, seit
    # #130 im Repo) definiert "Nachweisstufen A/B/C" ueber siebzehn Kriterien
    # in drei Stufen, und eine Stufe gilt erst, wenn ALLE ihre Kriterien
    # erfuellt sind - das reicht von der Aufzeichnung auf Lauf-Ebene bis zur
    # Uebergabeform und ist an einem einzelnen vorgelegten Paket gar nicht
    # feststellbar. Was hier geprueft wird, ist etwas anderes; es trueg denselben
    # Namen und wuerde als dieselbe Aussage gelesen. Nach unserer eigenen Regel
    # ist ein Etikett ohne belegbare Quelle schlechter als kein Etikett.
    # Ausgegeben wird deshalb die Feststellungsliste: fuenf Merkmale (seit ap14 mit 1a), je ja oder
    # nein, jedes auf einen Schritt zurueckfuehrbar. Wer daraus eine Stufe
    # ableiten will, tut das gegen das Kriterienwerk und nicht gegen uns.
    feststellungen = [
        {
            "merkmal": "Auslieferungsliste gegen die gelieferten Dateien geprueft",
            "ergebnis": liefer_ergebnis,
            "schritt": "1b",
            "bedeutung": (
                "ohne sie ist nicht belegt, dass genau die versiegelten Dateien geliefert "
                "wurden; eine hinzugefuegte oder ausgetauschte Datei faellt nicht auf. "
                "'nicht anwendbar', wenn die Eingabe die nackte Paketdatei ist - dann gibt "
                "es keine gelieferten Dateien, die zu halten waeren. Fehlt dagegen die "
                "Liste im Umschlag, ist das ein Versaeumnis und heisst 'nein'"
            ),
        },
        {
            # ap14, Nachpruefung: eine nicht gemessene Inhaltsdatei stand
            # vorher nur als "uebersprungen" im Schritt, die Feststellung
            # lautete trotzdem "Alle Schritte bestanden". Sie ist ein offener
            # Punkt und steht deshalb hier.
            "merkmal": "gelieferte Inhaltsdatei gegen die versiegelte Nutzlast gehalten",
            "ergebnis": ("ja" if _stand("1a.") == BESTANDEN
                         else "nicht anwendbar" if not isinstance(envelope, dict)
                         else "nein"),
            "schritt": "1a",
            "bedeutung": (
                "ohne diesen Schritt ist nur die Kopie der Nutzlast im Paket (payload_b64) an "
                "das Siegel gebunden, nicht die Datei, die gelesen wird. 'nein' auch dann, wenn "
                "neben der nackten Paketdatei keine Inhaltsdatei liegt: gemessen ist dann "
                "nichts. 'nicht anwendbar' nur ohne Umschlag"
            ),
        },
        {
            "merkmal": "BagIt-Ablage nachgerechnet",
            "ergebnis": bagit_ergebnis,
            "schritt": "0",
            "bedeutung": (
                "Prueffsummen der Ablage gegen die Manifeste. 'nicht anwendbar', wenn die "
                "Eingabe die nackte Paketdatei ist - dann gibt es keine Ablage, die "
                "nachzurechnen waere"
            ),
        },
        {
            "merkmal": "externer Zeitstempel geprueft",
            "ergebnis": "ja" if anker_ok else "nein",
            "schritt": "4",
            "bedeutung": (
                "ohne Anker bezeugt niemand ausser uns den Zeitpunkt"
            ),
        },
        {
            "merkmal": "oeffentlicher Schluessel gegen die Historie aufgeloest",
            "ergebnis": "ja" if schluessel_unabhaengig else "nein",
            "schritt": "3c",
            "bedeutung": (
                "ein Paket, das seinen eigenen Schluessel mitbringt, bezeugt nur sich selbst. "
                "Das Merkmal verlangt deshalb die Aufloesung der key_id in der "
                "veroeffentlichten Schluesselhistorie (--key-history), einer Quelle ausserhalb "
                "des Pakets. Ein einzelner --public-key genuegt nicht: der Verifier kann nicht "
                "sehen, ob der Vorleger ihn der Historie oder dem Paket entnommen hat - und wer "
                "mit eigenem Schluesselpaar siegelt, legt seinen eigenen vor (A7a)"
            ),
        },
    ]
    offen = [f["merkmal"] for f in feststellungen if f["ergebnis"] == "nein"]
    unklar = [f["merkmal"] for f in feststellungen if f["ergebnis"] == "nicht anwendbar"]
    if failed:
        stufe = "nicht bestanden"
        stufe_grund = (
            "mindestens ein Schritt ist gescheitert: "
            + "; ".join(c["pruefung"] for c in failed)
            + ". Eine Feststellung wird dann nicht getroffen, unabhaengig von allem uebrigen."
        )
    else:
        stufe = "keine Stufe vergeben"
        stufe_grund = (
            ("Alle Schritte bestanden. " if not skipped else
             f"Kein Schritt gescheitert, {len(skipped)} nicht gemessen (uebersprungen). ")
            + "Ein Stufenbuchstabe wird bewusst nicht vergeben: die "
            "Nachweisstufen A/B/C aus docs/KRITERIENWERK.md sind ueber siebzehn Kriterien "
            "definiert, die an einem einzelnen Paket nicht feststellbar sind. Stattdessen die "
            "Feststellungen: "
            + (f"alle {len(feststellungen)} Merkmale erfuellt." if not offen and not unklar
               else ", ".join(
                   ([("offen ist " + " und ".join(offen))] if offen else [])
                   + ([("nicht anwendbar ist " + " und ".join(unklar))] if unklar else [])) + ".")
        )

    return {
        "checks": checks,
        "verdict": verdict,
        "passed": not failed,
        "stufe": stufe,
        "stufe_begruendung": stufe_grund,
        "feststellungen": feststellungen,
        "ungedeckte_dateien": ungedeckt,
        "envelope_version": str(seal.get("envelope_version")),
        "seal_version": str(seal.get("seal_version")),
    }


# ===========================================================================
# Teil 7b: Archiv-Zugehoerigkeitsnachweis (Z1 Teil 2, Issue #39/#66).
#
# Zweiter Eingabetyp dieses Verifiers, erkannt am package_type. Ein Kunde
# legt vor: SEINE Archiv-Index-Zeile, den Merkle-Pfad, das signierte
# Wochen-Manifest und dessen RFC-3161-Anker. Der Pruefer stellt damit fest,
# dass genau dieses Dokument zu einem extern bezeugten Bestand gehoerte -
# ohne die Dokumente anderer zu sehen und ohne unseren Bestand.
#
# Baum-Konstruktion identisch zum Siegel-Baum (RFC 6962, Domaenentrennung
# 0x00/0x01), deshalb dieselben Funktionen wie in Teil 2; Blatt-Eingabe ist
# hier der SHA-256 ueber die rohen Bytes der Index-Zeile.
# ===========================================================================

ARCHIVE_PROOF_TYPE = "phm-archiv-nachweis"
ARCHIVE_PROOF_VERSION = "1"
MANIFEST_VERSION = "1"
MANIFEST_SIG_ALGO = "ed25519"
MANIFEST_HASH_ALGO = "sha256"
# Feste Feldreihenfolge der signierten Manifest-Serialisierung, zweite
# Implementierung (nicht importiert), Referenz: docs/ARCHIV.md.
_MANIFEST_SIGNED_FIELDS = (
    "manifest_version",
    "sig_algo",
    "hash_algo",
    "key_id",
    "woche",
    "created_at",
    "manifest_nr",
    "tree_size",
    "root_hash",
    "index_pruefsumme",
    "stand",
    "prev_manifest_hash",
)
_ARCHIVE_PROOF_TOP_FIELDS = (
    "package_type",
    "package_version",
    "nachweis",
    "index_zeile",
    "manifest",
    "anker",
    "grenzen",
)

# Der zulaessige Inhalt von "grenzen" - byte-gleich mit NACHWEIS_GRENZEN in
# backend/src/archiv/wurzel.py (M-12 a, #201).
#
# Warum ein FESTER Wortlaut und nicht einfach ein erlaubtes Feld: A5 weist
# unbekannte Felder ab, weil ein frei befuellbares Feld ein Kanal waere -
# jemand mit Schreibzugriff auf das Paket koennte darin etwas
# hinaustransportieren. Ein Feld, dessen einzig zulaessiger Inhalt hier
# steht, traegt kein frei waehlbares Bit; abweichender Text ist ein Befund.
# Das Feld ist optional: Pakete, die vor dieser Fassung gebaut wurden,
# tragen es nicht und bleiben pruefbar.
_ARCHIVE_PROOF_GRENZEN = (
    "Ein Anker in diesem Paket belegt fuer sich genommen, dass ein "
    "Zeitstempel-Token vorliegt, dessen messageImprint die Wurzel des "
    "Manifests bezeugt. Ob die Zeitstempel-Stelle dieses Token wirklich "
    "signiert hat, ist damit NICHT belegt: die CMS-Signatur und die "
    "Zertifikatskette prueft nur, wer dem Pruefwerkzeug das Zertifikat der "
    "Stelle vorlegt (--tsa-cert) oder openssl ts -verify verwendet. "
    "Ohne diesen Schritt ist der Zeitpunkt eine Angabe, kein Beweis."
)
_ARCHIVE_PROOF_FIELDS = (
    "entry_id",
    "zeilen_hash",
    "leaf_index",
    "tree_size",
    "audit_path",
    "root_hash",
    "manifest_nr",
    "manifest_hash",
)
_WOCHE_RE = re.compile(r"^\d{4}-W\d{2}$")
_ZAHL_RE = re.compile(r"^(0|[1-9]\d*)$")


def manifest_signed_bytes(record: Any) -> bytes:
    """Signierte Serialisierung eines Wochen-Manifests v1 (Zweitimplementierung)."""
    if not isinstance(record, dict):
        raise PruefungGescheitert("manifest: Objekt erwartet")
    if record.get("manifest_version") != MANIFEST_VERSION:
        raise PruefungGescheitert(
            f"manifest_version: nur {MANIFEST_VERSION!r} wird von diesem Verifier getragen"
        )
    if record.get("sig_algo") != MANIFEST_SIG_ALGO:
        raise PruefungGescheitert(f"manifest.sig_algo: nur {MANIFEST_SIG_ALGO!r} wird getragen")
    if record.get("hash_algo") != MANIFEST_HASH_ALGO:
        raise PruefungGescheitert(f"manifest.hash_algo: nur {MANIFEST_HASH_ALGO!r} wird getragen")
    values: Dict[str, str] = {}
    for name in _MANIFEST_SIGNED_FIELDS:
        value = record.get(name)
        if not isinstance(value, str) or value == "" or "\n" in value:
            raise PruefungGescheitert(f"manifest.{name}: nicht-leerer String ohne Zeilenumbruch erwartet")
        values[name] = value
    if not _WOCHE_RE.match(values["woche"]):
        raise PruefungGescheitert("manifest.woche: Format YYYY-WNN erwartet")
    if not _TS_Z_RE.match(values["created_at"]):
        raise PruefungGescheitert("manifest.created_at: Format YYYY-MM-DDThh:mm:ssZ erwartet")
    for name in ("manifest_nr", "tree_size", "stand"):
        if not _ZAHL_RE.match(values[name]):
            raise PruefungGescheitert(f"manifest.{name}: Dezimalzahl ohne fuehrende Nullen erwartet")
    for name in ("root_hash", "prev_manifest_hash"):
        if not _SHA256_RE.match(values[name]):
            raise PruefungGescheitert(f"manifest.{name}: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    if not _DIGEST_RE.match(values["index_pruefsumme"]):
        raise PruefungGescheitert("manifest.index_pruefsumme: 'sha256:<hex>' erwartet")
    return "\n".join(f"{name}:{values[name]}" for name in _MANIFEST_SIGNED_FIELDS).encode("utf-8")


def verify_archive_manifest(record: Any, public_key_hex: Optional[str] = None,
                            key_history: Optional[Dict[str, Dict[str, Any]]] = None,
                            ) -> Dict[str, Any]:
    """
    Prueft ein Wochen-Manifest: Serialisierung, Ed25519-Signatur,
    manifest_hash (bindet Inhalt UND Signatur), key_id im Raum "am-".
    Liefert, gegen welchen Schluessel geprueft wurde. Wirft
    PruefungGescheitert.
    """
    message = manifest_signed_bytes(record)
    embedded = record.get("public_key")
    if not isinstance(embedded, str) or not re.match(r"^[0-9a-f]{64}$", embedded):
        raise PruefungGescheitert("manifest.public_key: 32 Byte Hex (Kleinbuchstaben) erwartet")
    # key_id-Raum "am-" (Archiv-Manifest), getrennt vom Belegakten-Siegel "ba-":
    # eine Verwechslung der beiden Schluessel faellt schon an der Kennung auf.
    erwartet = "am-" + hashlib.sha256(bytes.fromhex(embedded)).hexdigest()[:16]
    if record.get("key_id") != erwartet:
        raise PruefungGescheitert(
            "manifest.key_id: passt nicht zum oeffentlichen Schluessel oder liegt nicht "
            "im Raum 'am-' (Archiv-Manifest)"
        )
    signature = record.get("signature")
    if not isinstance(signature, str) or not _ED25519_SIG_RE.match(signature):
        raise PruefungGescheitert("manifest.signature: fehlt oder hat kein Ed25519-Hex-Format")
    # Dieselbe Aufloesung wie beim Kopf: ueber die key_id gegen die
    # veroeffentlichte Historie, samt Gueltigkeitsfenster. Ohne das setzte die
    # Manifest-Pruefung EINEN Schluessel fuer ALLE Manifeste voraus und brach
    # an der ersten Rotation - waehrend die Koepfe daneben sauber aufgeloest
    # wurden.
    if key_history is not None:
        _gegen_historie(record, embedded, "Manifest", key_history)
    # Der vorgelegte Schluessel wird ZUERST gegen den mitgefuehrten gehalten:
    # ein fremd signiertes Manifest ist in sich stimmig, der Befund ist dann
    # der Schluessel und nicht die Signatur. Sonst meldete der Verifier den
    # Folgefehler statt der Ursache.
    #
    # VORRANG (#161): liegt eine Historie vor, wird der EINZELNE Schluessel
    # nicht zusaetzlich angewandt. Konjunktiv angewandt scheitert die
    # Kombination ueber einem rotierten Abzug zwangslaeufig - ein Schluessel
    # kann nicht zu allen Manifesten passen, sonst gaebe es die Rotation
    # nicht. Der Bericht sagt das (siehe _schluessel_herkunft), die CLI sagt
    # es zusaetzlich beim Aufruf.
    vorgelegt_passt = None
    if public_key_hex is not None and key_history is None:
        vorgelegt_passt = public_key_hex.lower() == embedded
        if not vorgelegt_passt:
            raise PruefungGescheitert(
                "der vorgelegte oeffentliche Schluessel ist NICHT der im Manifest gefuehrte - "
                "entweder ist der Schluessel falsch oder das Manifest stammt aus fremder Hand "
                f"(vorgelegt {public_key_hex.lower()[:16]}..., im Manifest {embedded[:16]}...)"
            )
    if not ed25519_verify(bytes.fromhex(embedded), message, bytes.fromhex(signature)):
        raise PruefungGescheitert(
            "manifest.signature: verifiziert nicht (Manifest veraendert oder fremder Schluessel)"
        )
    if record.get("manifest_hash") != hashlib.sha256(
        message + b"\n" + signature.encode("ascii")
    ).hexdigest():
        raise PruefungGescheitert("manifest.manifest_hash: passt nicht zu Inhalt und Signatur")
    return {"key_id": record.get("key_id"), "vorgelegt_passt": vorgelegt_passt}


def load_archive_proof(path: str) -> Dict[str, Any]:
    """Liest ein Nachweis-Paket (JSON) und prueft seine Grobstruktur."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            proof = json.load(fh)
    except OSError as e:
        raise PaketFehler(f"Nachweis nicht lesbar: {e}")
    except ValueError as e:
        raise PaketFehler(f"Nachweis ist kein gueltiges JSON: {e}")
    if not isinstance(proof, dict) or proof.get("package_type") != ARCHIVE_PROOF_TYPE:
        raise PaketFehler(f"Nachweis: package_type {ARCHIVE_PROOF_TYPE!r} erwartet")
    if proof.get("package_version") != ARCHIVE_PROOF_VERSION:
        raise PaketFehler(
            f"Nachweis: package_version {proof.get('package_version')!r} wird von diesem "
            f"Verifier nicht getragen, nur {ARCHIVE_PROOF_VERSION!r}"
        )
    for feld in ("nachweis", "manifest"):
        if not isinstance(proof.get(feld), dict):
            raise PaketFehler(f"Nachweis: {feld}-Objekt fehlt")
    if not isinstance(proof.get("index_zeile"), str) or not proof["index_zeile"].strip():
        raise PaketFehler("Nachweis: index_zeile fehlt")
    return proof


def _archive_document_check(zeile: Dict[str, Any], dokument_pfad: str) -> str:
    """Vorgelegte Datei gegen die Prueffsumme IN der Index-Zeile."""
    try:
        h = hashlib.sha256()
        with open(dokument_pfad, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
    except OSError as e:
        raise PruefungGescheitert(f"Dokument nicht lesbar: {e}")
    pruefsummen = zeile.get("pruefsummen")
    if not isinstance(pruefsummen, dict) or not isinstance(pruefsummen.get("sha256"), str):
        raise PruefungGescheitert("index_zeile: kein sha256 unter 'pruefsummen' - Dokument nicht zuordenbar")
    if h.hexdigest() != pruefsummen["sha256"]:
        raise PruefungGescheitert(
            "die vorgelegte Datei hat NICHT die Prueffsumme der Index-Zeile "
            f"(Datei {h.hexdigest()}, Zeile {pruefsummen['sha256']})"
        )
    return h.hexdigest()


def verify_archive_proof(
    proof: Dict[str, Any],
    public_key_hex: Optional[str] = None,
    trusted_cert_der: Optional[Any] = None,
    dokument_pfad: Optional[str] = None,
    key_history: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Faehrt die Pruefschritte A1 bis A5 ueber einem Nachweis-Paket.

    key_history (Z2-F11, #162): dieselbe Aufloesung ueber die key_id, die der
    Verzeichnis-Pfad und das Siegel-Paket schon fahren. Vorher rief A3
    verify_archive_manifest OHNE Historie und empfahl daneben --public-key -
    also genau den Aufruf, der an der ersten Rotation bricht. Seit #142 ist
    das kein Gedankenspiel mehr: archiv_manifest_key_history.json fuehrt drei
    Eintraege, der produktive Schluessel signiert das Manifest des
    Produktivbestandes, der Demo-Schluessel das der Referenzakte. EIN
    --public-key kann diese beiden nicht zugleich pruefen.
    """
    checks: List[Dict[str, str]] = []
    nachweis = proof["nachweis"]
    manifest = proof["manifest"]
    zeile_bytes = proof["index_zeile"].encode("utf-8")
    zeile_hash = hashlib.sha256(zeile_bytes).hexdigest()
    zeile_obj: Optional[Dict[str, Any]] = None
    root_belegt = False

    # A1: Index-Zeile -> Blatt
    try:
        if nachweis.get("zeilen_hash") != zeile_hash:
            raise PruefungGescheitert(
                "der SHA-256 ueber die vorgelegte Index-Zeile ist nicht der Blatt-Hash des "
                f"Nachweises (Zeile {zeile_hash}, Nachweis {nachweis.get('zeilen_hash')})"
            )
        try:
            geladen = json.loads(proof["index_zeile"])
        except ValueError as e:
            raise PruefungGescheitert(f"index_zeile ist kein gueltiges JSON: {e}")
        if not isinstance(geladen, dict):
            raise PruefungGescheitert("index_zeile: JSON-Objekt erwartet")
        zeile_obj = geladen
        if zeile_obj.get("entry_id") != nachweis.get("entry_id"):
            raise PruefungGescheitert(
                f"index_zeile gehoert zu {zeile_obj.get('entry_id')!r}, der Nachweis lautet auf "
                f"{nachweis.get('entry_id')!r}"
            )
        detail = (
            f"SHA-256 ueber die rohen Zeilen-Bytes = Blatt-Eingabe {zeile_hash}; Eintrag "
            f"{zeile_obj.get('entry_id')}. Dieselbe Rechnung geht ohne dieses Skript: "
            "printf '%s' \"$(cat zeile.txt)\" | shasum -a 256."
        )
        checks.append(_check("A1. Index-Zeile: Blatt nachgerechnet", BESTANDEN, detail))
    except PruefungGescheitert as e:
        checks.append(_check("A1. Index-Zeile: Blatt nachgerechnet", NICHT_BESTANDEN, str(e)))

    # A1b: vorgelegtes Dokument gegen die Prueffsumme in der Zeile
    if dokument_pfad is None:
        checks.append(
            _check(
                "A1b. Vorgelegtes Dokument gegen die Index-Zeile",
                UEBERSPRUNGEN,
                "keine Datei vorgelegt (--dokument). Der Nachweis belegt dann die Zugehoerigkeit "
                "der ZEILE; dass eine bestimmte Datei gemeint ist, sagt erst der Vergleich mit "
                "ihrer Prueffsumme.",
            )
        )
    else:
        try:
            if zeile_obj is None:
                raise PruefungGescheitert("index_zeile nicht lesbar (Schritt A1), Dokument nicht zuordenbar")
            hexd = _archive_document_check(zeile_obj, dokument_pfad)
            checks.append(
                _check(
                    "A1b. Vorgelegtes Dokument gegen die Index-Zeile",
                    BESTANDEN,
                    f"SHA-256 der vorgelegten Datei = Prueffsumme der Index-Zeile ({hexd})",
                )
            )
        except PruefungGescheitert as e:
            checks.append(_check("A1b. Vorgelegtes Dokument gegen die Index-Zeile", NICHT_BESTANDEN, str(e)))

    # A2: Merkle-Pfad zur Wurzel
    try:
        try:
            leaf_index = int(nachweis.get("leaf_index"))
            tree_size = int(nachweis.get("tree_size"))
        except (TypeError, ValueError):
            raise PruefungGescheitert("nachweis.leaf_index/tree_size: Zahl erwartet")
        audit_path = nachweis.get("audit_path")
        if not isinstance(audit_path, list):
            raise PruefungGescheitert("nachweis.audit_path: Liste erwartet")
        root = str(nachweis.get("root_hash"))
        verify_merkle_membership(zeile_hash, leaf_index, tree_size, audit_path, root)
        checks.append(
            _check(
                "A2. Zugehoerigkeitsnachweis (Merkle-Pfad, RFC 6962)",
                BESTANDEN,
                f"das Blatt fuehrt ueber {len(audit_path)} Knoten zur Wurzel {root} "
                f"(Bestand mit {tree_size} Eintraegen, Position {leaf_index + 1})",
            )
        )
    except PruefungGescheitert as e:
        checks.append(_check("A2. Zugehoerigkeitsnachweis (Merkle-Pfad, RFC 6962)", NICHT_BESTANDEN, str(e)))

    # A3: Manifest ueber der Wurzel
    try:
        info = verify_archive_manifest(manifest, public_key_hex, key_history)
        if manifest.get("root_hash") != nachweis.get("root_hash"):
            raise PruefungGescheitert(
                "das Manifest bezeugt eine andere Wurzel als der Nachweis "
                f"(Manifest {manifest.get('root_hash')}, Nachweis {nachweis.get('root_hash')})"
            )
        if str(manifest.get("tree_size")) != str(nachweis.get("tree_size")):
            raise PruefungGescheitert(
                f"das Manifest bezeugt {manifest.get('tree_size')} Eintraege, der Nachweis "
                f"rechnet mit {nachweis.get('tree_size')}"
            )
        if nachweis.get("manifest_hash") not in (None, manifest.get("manifest_hash")):
            raise PruefungGescheitert("nachweis.manifest_hash passt nicht zum vorgelegten Manifest")
        # Derselbe Helfer wie im Verzeichnis- und Siegel-Pfad, keine zweite
        # Kopie des Textes (Z2-F11, #162). Vorher standen hier zwei eigene
        # Zweige, die die Historie gar nicht kannten: mit --key-history
        # gefahren, empfahl der Befund weiterhin --public-key - eine
        # Begruendung, die den gefahrenen Fall nicht nennt, schickt den
        # Pruefer in die falsche Richtung.
        herkunft = _schluessel_herkunft(public_key_hex, key_history)
        root_belegt = True
        checks.append(
            _check(
                "A3. Wochen-Manifest ueber der Wurzel (Ed25519)",
                BESTANDEN,
                f"Manifest {manifest.get('manifest_nr')}, Woche {manifest.get('woche')}, "
                f"key_id {info['key_id']}: Signatur und manifest_hash verifiziert, {herkunft}. "
                f"Vorgaenger-Hash {manifest.get('prev_manifest_hash')} (Kette der Wochen).",
            )
        )
    except PruefungGescheitert as e:
        checks.append(_check("A3. Wochen-Manifest ueber der Wurzel (Ed25519)", NICHT_BESTANDEN, str(e)))

    # A4: externe Anker auf die Wurzel
    anker = proof.get("anker") or []
    if not isinstance(anker, list):
        anker = []
    if not anker:
        checks.append(
            _check(
                "A4. Externer Anker auf die Wurzel (RFC 3161)",
                UEBERSPRUNGEN,
                "das Paket enthaelt keinen Anker. Zugehoerigkeit ist damit belegt, ein "
                "ZEITPUNKT nicht: die Wurzel ist dann nur innerhalb unserer Reichweite bezeugt.",
            )
        )
    for idx, eintrag in enumerate(anker, start=1):
        zweck = (eintrag or {}).get("zweck") or "direkt"
        a = (eintrag or {}).get("anker") or {}
        wer = a.get("tsa_id") or "?"
        lbl = f"A4.{idx} Externer Anker auf die Wurzel ({wer}, {zweck})"
        lbl_cert = f"A4.{idx}b TSA-Zertifikat gegen Vertrauenszertifikat"
        try:
            if eintrag.get("root_hash") != nachweis.get("root_hash"):
                raise PruefungGescheitert("dieser Anker bezeugt eine andere Wurzel als der Nachweis")
            try:
                token_der = base64.b64decode(str(a.get("token_b64", "")), validate=True)
            except (ValueError, binascii.Error):
                raise PruefungGescheitert("anker.token_b64: keine gueltige Base64-Kodierung")
            if not token_der:
                raise PruefungGescheitert("anker.token_b64: leer")
            claimed = a.get("token_sha256")
            if claimed is not None and claimed != hashlib.sha256(token_der).hexdigest():
                raise PruefungGescheitert("anker.token_sha256 passt nicht zu den Token-Bytes")
            info = verify_timestamp_token(token_der, trusted_cert_der)
            if info["hash_algo_oid"] != OID_SHA256:
                raise PruefungGescheitert("messageImprint: Algorithmus ist nicht SHA-256")
            if info["hashed_message"] != str(nachweis.get("root_hash")):
                raise PruefungGescheitert(
                    "das Token bezeugt einen anderen Hash als die Wurzel des Nachweises "
                    f"(Token {info['hashed_message']}, Wurzel {nachweis.get('root_hash')})"
                )
            checks.append(
                _check(
                    lbl,
                    BESTANDEN,
                    f"messageImprint = Wurzel; TSA-Signatur ({info['signature_scheme']}) ueber den "
                    f"signierten Attributen verifiziert; genTime {info['gen_time']}, "
                    f"Signer-Zertifikat SHA-256 {info['signer_cert_sha256']}",
                )
            )
            if info["trusted_cert_match"] is None:
                checks.append(
                    _check(
                        lbl_cert,
                        UEBERSPRUNGEN,
                        "kein Vertrauenszertifikat vorgelegt (--tsa-cert); ob das Zertifikat im Token "
                        "der erwarteten TSA gehoert, muss der Pruefer selbst feststellen.",
                    )
                )
            elif info["trusted_cert_match"]:
                checks.append(_check(lbl_cert, BESTANDEN, "Signer-Zertifikat byte-identisch mit einem vorgelegten"))
            else:
                checks.append(
                    _check(lbl_cert, NICHT_BESTANDEN, "Signer-Zertifikat ist KEINES der vorgelegten")
                )
        except PruefungGescheitert as e:
            checks.append(_check(lbl, NICHT_BESTANDEN, str(e)))
            checks.append(_check(lbl_cert, UEBERSPRUNGEN, "Token-Pruefung gescheitert"))

    # A5: Der Nachweis zeigt nichts Fremdes. Das ist keine Zusicherung von
    # uns, sondern hier nachgesehen: unbekannte Felder waeren ein Kanal.
    try:
        fremd = [k for k in proof if k not in _ARCHIVE_PROOF_TOP_FIELDS]
        if fremd:
            raise PruefungGescheitert(f"unbekannte Felder im Paket: {', '.join(sorted(fremd))}")
        # "grenzen" ist zugelassen, aber nicht frei: nur der hier hinterlegte
        # Wortlaut. Sonst waere aus dem Vorbehalt genau der Kanal geworden,
        # den A5 verhindern soll (#201).
        if "grenzen" in proof and proof["grenzen"] != _ARCHIVE_PROOF_GRENZEN:
            raise PruefungGescheitert(
                "Feld 'grenzen' weicht vom hinterlegten Wortlaut ab - zulaessig ist "
                "genau der Vorbehalt, den dieses Werkzeug kennt, kein freier Text"
            )
        fremd_n = [k for k in nachweis if k not in _ARCHIVE_PROOF_FIELDS]
        if fremd_n:
            raise PruefungGescheitert(f"unbekannte Felder im Nachweis: {', '.join(sorted(fremd_n))}")
        pfad = nachweis.get("audit_path") or []
        if not all(isinstance(k, str) and _SHA256_RE.match(k) for k in pfad):
            raise PruefungGescheitert("audit_path enthaelt etwas anderes als Knoten-Hashes")
        checks.append(
            _check(
                "A5. Datensparsamkeit des Nachweises",
                BESTANDEN,
                f"genau eine Index-Zeile (die eigene) und {len(pfad)} Knoten-Hashes. Ein Knoten ist "
                "SHA-256 ueber Blatt- bzw. Knoten-Bytes; fremde Zeilen, fremde Dokument-Prueffsummen "
                "und fremde Kennungen sind daraus nicht rueckrechenbar und stehen nicht im Paket."
                + (
                    " Das Feld 'grenzen' traegt den hier hinterlegten Wortlaut und keinen "
                    "freien Text."
                    if "grenzen" in proof
                    else ""
                ),
            )
        )
    except PruefungGescheitert as e:
        checks.append(_check("A5. Datensparsamkeit des Nachweises", NICHT_BESTANDEN, str(e)))

    failed = [c for c in checks if c["ergebnis"] == NICHT_BESTANDEN]
    skipped = [c for c in checks if c["ergebnis"] == UEBERSPRUNGEN]
    if failed:
        verdict = (
            "NICHT BESTANDEN: mindestens eine Pruefung ist gescheitert. Die Zugehoerigkeit dieses "
            "Dokuments zum bezeugten Bestand ist mit diesem Nachweis nicht belegt."
        )
    else:
        verdict = "BESTANDEN im Umfang der durchgefuehrten Pruefungen."
        if skipped:
            verdict += " Uebersprungen (nicht geprueft): " + "; ".join(c["pruefung"] for c in skipped) + "."
        verdict += (
            " Belegt ist, dass dieser Eintrag zu dem Bestand gehoerte, ueber den das Manifest "
            "die Wurzel signiert hat"
            + (
                ", und dass dieser Bestand spaetestens zum Zeitpunkt im Zeitstempel-Token existierte"
                if anker and root_belegt
                else ""
            )
            + ". NICHT belegt und nicht Gegenstand dieser Pruefung ist, dass der Bestand "
            "VOLLSTAENDIG ist: ein Dokument, das nie archiviert wurde, fehlt hier unbemerkt "
            "(docs/ARCHIV.md, Abschnitt zur Vollstaendigkeit)."
        )
    return {
        "checks": checks,
        "verdict": verdict,
        "passed": not failed,
        "package_version": ARCHIVE_PROOF_VERSION,
        "manifest_version": str(manifest.get("manifest_version")),
    }


# ===========================================================================
# Teil 7c: Oeffentliches Verzeichnis der Archiv-Wurzeln beobachten (Z2).
#
# Dritter Eingabetyp: ein VERZEICHNIS-Abzug (verzeichnis.jsonl + koepfe/),
# so wie er veroeffentlicht wird. Format: docs/VERZEICHNIS.md.
#
# Zweck ist ein anderer als bei den beiden ersten Typen: dort wird EIN
# Nachweis geprueft, hier wird der veroeffentlichte BESTAND ueber die Zeit
# beobachtet. Die Aussage, die dabei entsteht, ist die einzige, die wir uns
# nicht selbst ausstellen koennen: dass alle denselben Bestand sehen und
# nichts nachtraeglich verschwindet.
#
# Was das NICHT ist: eine Voraussetzung fuer die Pruefung einer Belegakte.
# Die Schritte 0 bis 5 und A1 bis A5 oben laufen ohne dieses Verzeichnis,
# ohne Netz und ohne uns - daran aendert dieser Teil nichts.
# ===========================================================================

VERZEICHNIS_DATEI = "verzeichnis.jsonl"
KOPF_VERSION = "1"
PIN_TYPE = "phm-verzeichnis-anheftung"
PIN_VERSION = "1"
KONSISTENZ_PAKET_TYPE = "phm-verzeichnis-konsistenz"
# v2: das Paket traegt die beiden KOEPFE im Original (mit signature und
# public_key) statt eines eigens gebauten Ausweises ohne Signatur. Erst
# damit kann ein zweiter Beobachter unterscheiden, ob der Stand vom
# Uebermittler stammt oder von der Instanz (#155).
KONSISTENZ_PAKET_VERSION = "2"

_KOPF_SIGNED_FIELDS = (
    "kopf_version",
    "sig_algo",
    "hash_algo",
    "key_id",
    "created_at",
    "kopf_nr",
    "tree_size",
    "root_hash",
    "datei_pruefsumme",
    "prev_kopf_hash",
)

# Zulaessige Felder einer Verzeichnis-Zeile. Unbekannte Felder sind ein
# Befund, kein Detail: das Verzeichnis ist oeffentlich, jedes zusaetzliche
# Feld waere ein Kanal, durch den Inhalt nach draussen sickern koennte.
_ZEILE_GEMEINSAM = ("nr", "typ", "veroeffentlicht_at", "prev")
_ZEILE_FELDER = {
    "wurzel": _ZEILE_GEMEINSAM + ("manifest",),
    "anker": _ZEILE_GEMEINSAM + ("manifest_nr", "manifest_hash", "root_hash", "zweck", "anker"),
}
_ANKER_FELDER = (
    "anchor_ref", "anchor_type", "anchored_at", "gen_time", "hash_algo",
    "message_imprint", "seal_hash", "token_b64", "token_sha256", "tsa_id", "tsa_url",
)


def kanonische_zeile(obj: Any) -> bytes:
    """Kanonische Serialisierung einer Verzeichnis-Zeile (Zweitimplementierung)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def kopf_signed_bytes(kopf: Any) -> bytes:
    """Signierte Serialisierung eines Verzeichnis-Kopfes v1 (Zweitimplementierung)."""
    if not isinstance(kopf, dict):
        raise PruefungGescheitert("kopf: Objekt erwartet")
    if kopf.get("kopf_version") != KOPF_VERSION:
        raise PruefungGescheitert(
            f"kopf_version: nur {KOPF_VERSION!r} wird von diesem Verifier getragen"
        )
    if kopf.get("sig_algo") != "ed25519":
        raise PruefungGescheitert("kopf.sig_algo: nur 'ed25519' wird getragen")
    if kopf.get("hash_algo") != "sha256":
        raise PruefungGescheitert("kopf.hash_algo: nur 'sha256' wird getragen")
    values: Dict[str, str] = {}
    for name in _KOPF_SIGNED_FIELDS:
        value = kopf.get(name)
        if not isinstance(value, str) or value == "" or "\n" in value:
            raise PruefungGescheitert(f"kopf.{name}: nicht-leerer String ohne Zeilenumbruch erwartet")
        values[name] = value
    if not _TS_Z_RE.match(values["created_at"]):
        raise PruefungGescheitert("kopf.created_at: Format YYYY-MM-DDThh:mm:ssZ erwartet")
    for name in ("kopf_nr", "tree_size"):
        if not _ZAHL_RE.match(values[name]):
            raise PruefungGescheitert(f"kopf.{name}: Dezimalzahl ohne fuehrende Nullen erwartet")
    for name in ("root_hash", "prev_kopf_hash"):
        if not _SHA256_RE.match(values[name]):
            raise PruefungGescheitert(f"kopf.{name}: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    if not _DIGEST_RE.match(values["datei_pruefsumme"]):
        raise PruefungGescheitert("kopf.datei_pruefsumme: 'sha256:<hex>' erwartet")
    return "\n".join(f"{name}:{values[name]}" for name in _KOPF_SIGNED_FIELDS).encode("utf-8")


def lade_key_history(pfad: str) -> Dict[str, Dict[str, Any]]:
    """
    Liest die VEROEFFENTLICHTE Schluesselhistorie (backend/keys/*_key_history.json)
    und gibt sie als key_id -> Eintrag zurueck.

    Warum das einen einzelnen --public-key ersetzt: sobald ein Schluessel
    rotiert, tragen aeltere Koepfe die alte key_id und neuere die neue. Ein
    einziger vorgelegter Schluessel kann dann nicht beide bezeugen - die
    Beobachtung bricht genau an der Rotation ab, also an der Stelle, an der
    man am genauesten hinsehen will.
    """
    try:
        with open(pfad, "r", encoding="utf-8") as fh:
            roh = json.load(fh)
    except OSError as e:
        raise PaketFehler(f"Schluesselhistorie nicht lesbar: {e}")
    except ValueError as e:
        raise PaketFehler(f"Schluesselhistorie ist kein JSON: {e}")
    eintraege = roh.get("keys") if isinstance(roh, dict) else roh
    if not isinstance(eintraege, list):
        raise PaketFehler("Schluesselhistorie: Liste unter 'keys' erwartet")
    aus: Dict[str, Dict[str, Any]] = {}
    for i, e in enumerate(eintraege):
        if not isinstance(e, dict):
            raise PaketFehler(f"Schluesselhistorie[{i}]: Objekt erwartet")
        kid, pub = e.get("key_id"), e.get("public_key")
        if not isinstance(kid, str) or not kid:
            raise PaketFehler(f"Schluesselhistorie[{i}]: key_id fehlt")
        if not isinstance(pub, str) or not re.match(r"^[0-9a-f]{64}$", pub):
            raise PaketFehler(f"Schluesselhistorie[{i}] ({kid}): public_key ist kein 32-Byte-Hex")
        if kid in aus:
            raise PaketFehler(f"Schluesselhistorie: key_id {kid} kommt doppelt vor")
        # Format wie bei created_at (Z2-F8, #159). Vorher ungeprueft: ein
        # Fenster in abweichender Form vergleicht STILL FALSCH, weil
        # _im_gueltigkeitsfenster Zeichenketten vergleicht. "2026-08-04"
        # gegen "2026-08-04T10:00:00Z" liefert ein Ergebnis, nur nicht das
        # gemeinte, und niemand sieht es. Ein Fenster, das nicht vergleichbar
        # ist, ist ein Befund - kein stiller Vergleich.
        for feld in ("valid_from", "valid_to"):
            wert = e.get(feld)
            if wert is None:
                continue
            if not isinstance(wert, str) or not _TS_Z_RE.match(wert):
                raise PaketFehler(
                    f"Schluesselhistorie[{i}] ({kid}): {feld} {wert!r} - erwartet wird "
                    "das Format YYYY-MM-DDThh:mm:ssZ oder null. Eine Zeitangabe in "
                    "anderer Form wuerde als Zeichenkette verglichen und ergaebe "
                    "lautlos ein falsches Urteil ueber das Gueltigkeitsfenster")
        aus[kid] = {
            "key_id": kid,
            "public_key": pub,
            "valid_from": e.get("valid_from"),
            "valid_to": e.get("valid_to"),
            "note": e.get("note") or "",
        }
    if not aus:
        raise PaketFehler(
            "Schluesselhistorie ist leer - dann ist sie kein unabhaengiger Bezugspunkt "
            "(derselbe Befund wie in der Gate-A-Probe zur leeren Siegel-Historie)")
    return aus


def _fenster_lage(objekte: Sequence[Dict[str, Any]],
                  key_history: Dict[str, Dict[str, Any]]) -> str:
    """Was am Gueltigkeitsfenster WIRKLICH verglichen wurde (Z2-F8, #159).

    Der Berichtstext behauptete unbedingt "Gueltigkeitsfenster geprueft".
    `_im_gueltigkeitsfenster` vergleicht aber nur gegen gesetzte Grenzen und
    gibt bei `None` kommentarlos "im Fenster" zurueck - bei einem Eintrag ohne
    jede Angabe wurde also nichts verglichen, und der Bericht sagte das
    Gegenteil. Ein gruener Test faehrt genau diesen Fall.

    Deshalb zaehlt diese Funktion die drei Lagen ab und laesst den Bericht
    sagen, welche vorlagen. Nichts vergleichen zu koennen ist kein Fehler -
    es als Pruefung auszugeben schon.
    """
    beidseitig = offen = ohne = 0
    for objekt in objekte:
        eintrag = key_history.get(objekt.get("key_id"))
        if eintrag is None:
            continue
        von, bis = eintrag.get("valid_from"), eintrag.get("valid_to")
        if von and bis:
            beidseitig += 1
        elif von or bis:
            offen += 1
        else:
            ohne += 1
    teile = []
    if beidseitig:
        teile.append(f"{beidseitig} beidseitig begrenzt")
    if offen:
        teile.append(f"{offen} einseitig (valid_to null heisst: laeuft noch)")
    if ohne:
        teile.append(f"{ohne} OHNE jede Angabe - dort wurde kein Fenster verglichen")
    if not teile:
        return "Gueltigkeitsfenster: nichts zu vergleichen"
    return "Gueltigkeitsfenster " + ", ".join(teile)


def _rotation_erklaert(vorige: Any, jetzige: Any, key_history: Dict[str, Dict[str, Any]],
                       created_at: Any) -> Optional[str]:
    """Ist der Schluesselwechsel vorige -> jetzige erklaert? Sonst der Grund.

    EINE Regel fuer Manifeste (V2) und Koepfe (V4). Vorher stand sie nur bei
    den Koepfen: die MANIFESTE trugen dieselbe Rotation ungeprueft, ein
    offener Vorgaenger lief dort durch (gemessen: V2 bestanden, V4 nicht
    bestanden am selben Abzug). Dieselbe Begruendung, die
    `_gegen_historie` fuer die Aufloesung gibt - ein Verzeichnis, dessen
    Koepfe geprueft werden und dessen Manifeste nicht, bricht an der Rotation
    trotzdem ab.

    `valid_to: null` heisst "laeuft noch", nicht "kein Fenster" (Z2-F8, #159):
    signiert ein anderer Schluessel, waehrend der vorige laut Historie noch
    gilt, sind das zwei gleichzeitig gueltige Schluessel und keine Rotation.
    """
    if vorige == jetzige:
        return None
    fehlend = [k for k in (vorige, jetzige) if k not in key_history]
    if fehlend:
        return (f"Schluesselwechsel von {vorige} auf {jetzige}, aber "
                + ", ".join(str(k) for k in fehlend)
                + " steht nicht in der Schluesselhistorie - ein unerklaerter Wechsel")
    bis = key_history[vorige].get("valid_to")
    if bis is None:
        return (f"mit {jetzige} signiert, obwohl {vorige} laut Historie noch gilt "
                "(valid_to null) - ein Wechsel ohne abgelegten Vorgaenger ist keine "
                "erklaerte Rotation, sondern ein zweiter gleichzeitig gueltiger Schluessel")
    if isinstance(bis, str) and bis and isinstance(created_at, str) and created_at < bis:
        return f"mit {jetzige} signiert, obwohl {vorige} laut Historie noch bis {bis} galt"
    return None


def _schluessel_herkunft(public_key_hex: Optional[str],
                         key_history: Optional[Dict[str, Dict[str, Any]]],
                         fenster_lage: Optional[str] = None) -> str:
    """
    Benennt, WOGEGEN die Signaturen tatsaechlich geprueft wurden.

    Frueher stand hier bei gesetzter Historie ohne --public-key weiterhin
    "bezeugt sich in diesem Punkt selbst" samt Empfehlung, --public-key zu
    verwenden - also genau der Aufruf, von dem beide Docs inzwischen abraten.
    Eine Begruendung, die den gefahrenen Fall nicht nennt, ist schlimmer als
    keine: sie schickt den Pruefer in die falsche Richtung.
    """
    if key_history is not None:
        # Kein "und zusaetzlich gegen den vorgelegten Einzelschluessel" mehr:
        # das war die Beschreibung einer konjunktiven Anwendung, die ueber
        # einem rotierten Abzug garantiert scheiterte (#161). Die Historie hat
        # Vorrang, und dass der Einzelschluessel dabei UNANGEWANDT bleibt,
        # gehoert in den Bericht - nicht nur in die Kommandozeile.
        zusatz = (". Ein zusaetzlich vorgelegter --public-key wurde dabei NICHT angewandt: "
                  "die Historie hat Vorrang, ein einzelner Schluessel kann ueber einer "
                  "Rotation nicht zu allen Objekten passen"
                  if public_key_hex else "")
        # Bedingt formuliert: was verglichen wurde, steht da - nicht, was
        # verglichen worden waere, wenn die Historie Grenzen genannt haette.
        fenster = fenster_lage or "Gueltigkeitsfenster soweit angegeben"
        return ("ueber die key_id gegen die VORGELEGTE Schluesselhistorie aufgeloest "
                f"(Eintrag und oeffentlicher Schluessel geprueft; {fenster})"
                + zusatz)
    if public_key_hex:
        return ("gegen den VORGELEGTEN einzelnen oeffentlichen Schluessel (haelt nur, solange "
                "nicht rotiert wurde; --key-history loest je Objekt ueber die key_id auf)")
    return ("gegen den je Objekt mitgefuehrten Schluessel - bezeugt sich in diesem Punkt "
            "SELBST. Mit --key-history (veroeffentlichte Schluesselhistorie) faellt das weg")


def _im_gueltigkeitsfenster(eintrag: Dict[str, Any], zeitpunkt: Any) -> Optional[str]:
    """None, wenn der Zeitpunkt im Fenster liegt, sonst der Grund."""
    if not isinstance(zeitpunkt, str) or not zeitpunkt:
        return None                      # ohne Zeitangabe kein Urteil ueber das Fenster
    von, bis = eintrag.get("valid_from"), eintrag.get("valid_to")
    if isinstance(von, str) and von and zeitpunkt < von:
        return f"liegt VOR dem Beginn der Gueltigkeit ({zeitpunkt} < {von})"
    if isinstance(bis, str) and bis and zeitpunkt > bis:
        return f"liegt NACH dem Ende der Gueltigkeit ({zeitpunkt} > {bis})"
    return None


def _gegen_historie(objekt: Dict[str, Any], embedded: str, art: str,
                    key_history: Dict[str, Dict[str, Any]]) -> None:
    """
    Loest den Schluessel eines signierten Objekts (Manifest oder Kopf) ueber
    seine key_id in der veroeffentlichten Historie auf und prueft das
    Gueltigkeitsfenster. Dieselbe Aufloesung fuer beide Objektarten - ein
    Verzeichnis, dessen KOEPFE gegen die Historie geprueft werden, waehrend
    seine MANIFESTE einen einzigen Schluessel fuer alle voraussetzen, bricht
    an der Rotation trotzdem ab.
    """
    kid = objekt.get("key_id")
    eintrag = key_history.get(kid)
    if eintrag is None:
        raise PruefungGescheitert(
            f"{art}.key_id {kid!r} steht NICHT in der vorgelegten Schluesselhistorie - "
            "ein Schluesselwechsel, den niemand erklaert hat")
    if eintrag["public_key"] != embedded:
        raise PruefungGescheitert(
            f"key_id {eintrag['key_id']} fuehrt in der Historie den Schluessel "
            f"{eintrag['public_key'][:16]}..., im {art} steht {embedded[:16]}...")
    grund = _im_gueltigkeitsfenster(eintrag, objekt.get("created_at"))
    if grund:
        raise PruefungGescheitert(
            f"{art} vom {objekt.get('created_at')} ist mit {eintrag['key_id']} signiert, "
            f"aber dieser Schluessel {grund}")


def verify_verzeichnis_kopf(kopf: Any, public_key_hex: Optional[str] = None,
                            key_history: Optional[Dict[str, Dict[str, Any]]] = None,
                            ) -> Dict[str, Any]:
    """
    Prueft einen Verzeichnis-Kopf: Serialisierung, Ed25519-Signatur,
    kopf_hash (bindet Inhalt UND Signatur), key_id im Raum "am-" (derselbe
    Schluessel wie die Wochen-Manifeste, docs/VERZEICHNIS.md).
    """
    message = kopf_signed_bytes(kopf)
    embedded = kopf.get("public_key")
    if not isinstance(embedded, str) or not re.match(r"^[0-9a-f]{64}$", embedded):
        raise PruefungGescheitert("kopf.public_key: 32 Byte Hex (Kleinbuchstaben) erwartet")
    erwartet = "am-" + hashlib.sha256(bytes.fromhex(embedded)).hexdigest()[:16]
    if kopf.get("key_id") != erwartet:
        raise PruefungGescheitert(
            "kopf.key_id: passt nicht zum oeffentlichen Schluessel oder liegt nicht im Raum 'am-'"
        )
    signature = kopf.get("signature")
    if not isinstance(signature, str) or not _ED25519_SIG_RE.match(signature):
        raise PruefungGescheitert("kopf.signature: fehlt oder hat kein Ed25519-Hex-Format")

    # Gegen die veroeffentlichte Historie: der Schluessel wird ueber seine
    # key_id AUFGELOEST, nicht als einzelner Wert vorgelegt. Ein Wechsel ist
    # damit kein Bruch, sondern muss in der Historie ERKLAERT sein.
    if key_history is not None:
        _gegen_historie(kopf, embedded, "Kopf", key_history)

    # Vorrang wie beim Manifest (#161): mit Historie gilt die Aufloesung ueber
    # die key_id, ein zusaetzlich vorgelegter Einzelschluessel wird NICHT
    # angewandt. Sonst braeche jeder rotierte Abzug an dieser Zeile.
    vorgelegt_passt = None
    if public_key_hex is not None and key_history is None:
        vorgelegt_passt = public_key_hex.lower() == embedded
        if not vorgelegt_passt:
            raise PruefungGescheitert(
                "der vorgelegte oeffentliche Schluessel ist NICHT der im Kopf gefuehrte - "
                "entweder ist der Schluessel falsch oder das Verzeichnis stammt aus fremder Hand "
                f"(vorgelegt {public_key_hex.lower()[:16]}..., im Kopf {embedded[:16]}...)"
            )
    if not ed25519_verify(bytes.fromhex(embedded), message, bytes.fromhex(signature)):
        raise PruefungGescheitert(
            "kopf.signature: verifiziert nicht (Kopf veraendert oder fremder Schluessel)"
        )
    if kopf.get("kopf_hash") != hashlib.sha256(
        message + b"\n" + signature.encode("ascii")
    ).hexdigest():
        raise PruefungGescheitert("kopf.kopf_hash: passt nicht zu Inhalt und Signatur")
    return {"key_id": kopf.get("key_id"), "vorgelegt_passt": vorgelegt_passt}


def verify_merkle_consistency(
    alte_groesse: int,
    alte_wurzel: str,
    neue_groesse: int,
    neue_wurzel: str,
    proof: Sequence[str],
) -> None:
    """
    Konsistenznachweis nach RFC 6962 2.1.4 (Zweitimplementierung): der
    spaetere Stand enthaelt den frueheren unveraendert als Anfangsstueck.
    """
    if alte_groesse > neue_groesse:
        raise PruefungGescheitert(
            f"der angeheftete Stand ist groesser ({alte_groesse}) als der vorgelegte "
            f"({neue_groesse}) - das Verzeichnis ist geschrumpft, append-only verletzt"
        )
    for name, wert in (("alte_wurzel", alte_wurzel), ("neue_wurzel", neue_wurzel)):
        if not isinstance(wert, str) or not _SHA256_RE.match(wert):
            raise PruefungGescheitert(f"{name}: 64 Hex-Zeichen in Kleinbuchstaben erwartet")
    knoten_liste = list(proof or [])
    if not all(isinstance(k, str) and _SHA256_RE.match(k) for k in knoten_liste):
        raise PruefungGescheitert("Konsistenzpfad: enthaelt etwas anderes als Knoten-Hashes")
    if alte_groesse == neue_groesse:
        if knoten_liste:
            raise PruefungGescheitert("Konsistenzpfad: bei gleicher Groesse ist kein Pfad zulaessig")
        if alte_wurzel != neue_wurzel:
            raise PruefungGescheitert(
                "gleiche Groesse, verschiedene Wurzeln - zwei unvereinbare Staende "
                "desselben Verzeichnisses (BRUCH)"
            )
        return
    if alte_groesse == 0:
        if knoten_liste:
            raise PruefungGescheitert("Konsistenzpfad: der leere Baum braucht keinen Pfad")
        return
    knoten = iter([bytes.fromhex(k) for k in knoten_liste])

    def _naechster(wofuer: str) -> bytes:
        try:
            return next(knoten)
        except StopIteration:
            raise PruefungGescheitert(f"Konsistenzpfad: zu kurz ({wofuer} fehlt)")

    pos, letzte = alte_groesse - 1, neue_groesse - 1
    while pos % 2:
        pos //= 2
        letzte //= 2
    if pos:
        alt = neu = _naechster("Startknoten")
    else:
        alt = neu = bytes.fromhex(alte_wurzel)
    while pos:
        if pos % 2:
            geschwister = _naechster("Geschwisterknoten")
            alt = _mt_node_hash(geschwister, alt)
            neu = _mt_node_hash(geschwister, neu)
        elif pos < letzte:
            neu = _mt_node_hash(neu, _naechster("Geschwisterknoten"))
        pos //= 2
        letzte //= 2
    while letzte:
        neu = _mt_node_hash(neu, _naechster("Geschwisterknoten"))
        letzte //= 2
    if next(knoten, None) is not None:
        raise PruefungGescheitert("Konsistenzpfad: laenger als der Nachweis braucht")
    if alt.hex() != alte_wurzel:
        raise PruefungGescheitert(
            "der Nachweis fuehrt nicht zur angehefteten FRUEHEREN Wurzel: der spaetere Stand "
            "enthaelt den frueheren NICHT (entfernt, ersetzt oder umsortiert) - BRUCH"
        )
    if neu.hex() != neue_wurzel:
        raise PruefungGescheitert("der Nachweis fuehrt nicht zur behaupteten spaeteren Wurzel")


def merkle_consistency_path(alte_groesse: int, blatt_hashes: Sequence[str]) -> List[str]:
    """
    Konsistenzpfad nach RFC 6962 2.1.2 (SUBPROOF). Der Verifier bildet ihn
    selbst, weil er alle Zeilen vor sich hat; ein Beobachter muss ihn von
    uns also nicht erbitten - und kann ihn deshalb auch nicht von uns
    faelschen lassen.
    """
    def _sub(m: int, leaves: Sequence[bytes], b: bool) -> List[bytes]:
        n = len(leaves)
        if m == n:
            return [] if b else [_mt_root_raw(leaves)]
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            return _sub(m, leaves[:k], b) + [_mt_root_raw(leaves[k:])]
        return _sub(m - k, leaves[k:], False) + [_mt_root_raw(leaves[:k])]

    n = len(blatt_hashes)
    if not (0 <= alte_groesse <= n) or alte_groesse in (0, n):
        return []
    return [k.hex() for k in _sub(alte_groesse, [_mt_leaf_hash(h) for h in blatt_hashes], True)]


def load_verzeichnis(pfad: str) -> Dict[str, Any]:
    """Liest einen Verzeichnis-Abzug (Ordner mit verzeichnis.jsonl + koepfe/)."""
    datei = pfad if os.path.isfile(pfad) else os.path.join(pfad, VERZEICHNIS_DATEI)
    ordner = os.path.dirname(os.path.abspath(datei))
    try:
        with open(datei, "rb") as fh:
            rohdaten = fh.read()
    except OSError as e:
        raise PaketFehler(f"Verzeichnis nicht lesbar: {e}")
    rohe = [z for z in rohdaten.split(b"\n") if z.strip()]
    koepfe: List[Dict[str, Any]] = []
    koepfe_dir = os.path.join(ordner, "koepfe")
    if os.path.isdir(koepfe_dir):
        for name in sorted(os.listdir(koepfe_dir)):
            if not (name.startswith("kopf_") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(koepfe_dir, name), "r", encoding="utf-8") as fh:
                    koepfe.append(json.load(fh))
            except (OSError, ValueError) as e:
                raise PaketFehler(f"Kopf {name} nicht lesbar oder kein JSON: {e}")
    if not koepfe:
        raise PaketFehler(
            f"kein Kopf unter {koepfe_dir} - ohne signierten Kopf ist das eine Datei, "
            "kein Verzeichnis"
        )
    # anker/ wird von spiegeln() mitkopiert, hier aber frueher nie gelesen:
    # die Anker AUF DEN KOPF blieben damit ungeprueft, obwohl sie im Abzug
    # liegen. Genau daran haengt, ob der veroeffentlichte Stand einen von
    # aussen bezeugten Zeitpunkt hat (Schritt V7).
    kopf_anker: List[Dict[str, Any]] = []
    anker_dir = os.path.join(ordner, "anker")
    if os.path.isdir(anker_dir):
        for name in sorted(os.listdir(anker_dir)):
            if not (name.startswith("anker_") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(anker_dir, name), "r", encoding="utf-8") as fh:
                    kopf_anker.append(json.load(fh))
            except (OSError, ValueError) as e:
                raise PaketFehler(f"Anker {name} nicht lesbar oder kein JSON: {e}")
    return {
        "datei": datei,
        "rohe_zeilen": rohe,
        "datei_sha256": hashlib.sha256(rohdaten).hexdigest(),
        "koepfe": koepfe,
        "kopf_anker": kopf_anker,
    }


def load_pin(pfad: str) -> Dict[str, Any]:
    """Liest einen angehefteten Stand (das, was ein Beobachter aufbewahrt)."""
    try:
        with open(pfad, "r", encoding="utf-8") as fh:
            pin = json.load(fh)
    except OSError as e:
        raise PaketFehler(f"Anheftung nicht lesbar: {e}")
    except ValueError as e:
        raise PaketFehler(f"Anheftung ist kein gueltiges JSON: {e}")
    if not isinstance(pin, dict) or pin.get("paket_typ") != PIN_TYPE:
        raise PaketFehler(f"Anheftung: paket_typ {PIN_TYPE!r} erwartet")
    for feld in ("kopf_nr", "kopf_hash", "tree_size", "root_hash"):
        if not isinstance(pin.get(feld), str) or not pin[feld]:
            raise PaketFehler(f"Anheftung: {feld} fehlt")
    return pin


def _kopfkette_ab_pin(koepfe: Sequence[Dict[str, Any]], ab_nr: str,
                      alt: Any, neu: Any) -> Optional[str]:
    """Traegt die Kopf-Kette ab dem angehefteten Stand genau die erwartete Folge?

    Zwei Faelle, EIN Pfad - und das ist der Punkt. Der zweite Fall ist beim
    ersten Anlauf durchgerutscht und stand still da:

    - Der Schluessel ist heute derselbe wie im Pin. Dann muss er es die ganze
      Strecke gewesen sein. **A -> B -> A** bestand vorher anstandslos, und der
      Bericht sagte sogar "der Schluessel ist unveraendert gegenueber Ihrem
      angehefteten Stand" - ein fremder Schluessel hatte dazwischen
      unterschrieben und zurueckgegeben. Genau das Wegschauen, das #146
      abstellt, eine Ebene kleiner.
    - Der Schluessel hat gewechselt. Dann genau EIN Uebergang, alt -> neu. Ein
      Hin und Her ist keine Rotation, sondern zwei Parteien, die abwechselnd
      unterschreiben.

    Liefert None, wenn die Folge stimmt, sonst den Grund.
    """
    try:
        start = next(i for i, k in enumerate(koepfe) if k.get("kopf_nr") == ab_nr)
    except StopIteration:
        return f"Kopf {ab_nr} kommt in der Kette nicht vor"
    folge = [k.get("key_id") for k in koepfe[start:]]
    fremde = [k for k in folge if k not in (alt, neu)]
    if fremde:
        # Deckt beide Faelle ab: bei alt == neu ist JEDER andere Schluessel
        # fremd, also faellt der Ausflug A -> B -> A schon hier - eine eigene
        # Verzweigung dafuer waere toter Code.
        return ("ab dem angehefteten Stand unterschreiben noch andere Schluessel: "
                + ", ".join(sorted({str(k) for k in fremde}))
                + f" (Folge ab Kopf {ab_nr}: " + " -> ".join(str(k) for k in folge) + ")")
    wechsel = [(a, b) for a, b in zip(folge, folge[1:]) if a != b]
    gezeigt = " -> ".join(str(k) for k in folge)
    if alt == neu:
        return None
    if len(wechsel) != 1 or wechsel[0] != (alt, neu):
        return (f"die Folge der Schluessel ab Kopf {ab_nr} ist {gezeigt}"
                f"; erwartet war genau ein Uebergang {alt} -> {neu}")
    return None


def _pin_schluessel_gegen_abzug(
    pin: Dict[str, Any],
    pin_kopf: Optional[Dict[str, Any]],
    juengster: Dict[str, Any],
    key_history: Optional[Dict[str, Dict[str, Any]]],
    koepfe: Sequence[Dict[str, Any]] = (),
) -> str:
    """Der Schluessel aus dem Pin gegen den Schluessel des heutigen Abzugs (Z2-F2, #146).

    Warum ausgerechnet hier: `lade_key_history` liest eine beliebige lokale
    JSON-Datei - kein Siegel, kein Anker. Wer den Abzug ausliefert, kann eine
    passende Historie mitliefern, und V4 wird gruen, weil V4 die Rotation
    gegen genau diese mitgelieferte Datei haelt. Der Pin ist das EINZIGE
    Stueck Zustand, das beim Beobachter liegt und nicht vom Herausgeber kommt.
    Er fuehrt `key_id` und `public_key` seit jeher mit - verglichen wurden sie
    nie. Damit fuehrte der Beobachter genau die Angabe mit, gegen die er
    haette pruefen muessen, und tat es nicht.

    Rotation ist vorgesehen und deshalb kein Fehlschlag. Sie muss aber
    ERKLAERT sein, und zwar so, dass die Erklaerung nicht allein aus der
    mitgelieferten Datei stammt:

    1. der Kopf, den der Beobachter angeheftet hat, liegt noch im Abzug und
       traegt noch denselben Schluessel,
    2. die mitgelieferte Historie kennt den angehefteten Schluessel MIT
       DEMSELBEN public_key - wer die Historie faelscht, muss diesen Eintrag
       stehen lassen, sonst widerspricht sie dem, was der Beobachter selbst
       gesehen hat,
    3. der neue Schluessel steht in der Historie, sein Fenster passt zum
       juengsten Kopf, und das Fenster des alten war zu dem Zeitpunkt zu.

    Liefert den Satz fuer den Bericht; ein Bruch wird geworfen.
    """
    pin_kid = pin.get("key_id")
    pin_pub = pin.get("public_key")
    if not pin_kid and not pin_pub:
        return (" Der angeheftete Stand fuehrt keinen Schluessel mit (Pin aus einem Lauf vor "
                "#146) - an dieser Stelle ist nichts zu vergleichen, und der naechste Pin "
                "traegt ihn.")

    # 1. Der angeheftete Kopf muss noch da sein und noch denselben Schluessel tragen.
    if pin_kopf is None:
        raise PruefungGescheitert(
            f"Kopf {pin['kopf_nr']}, den Sie angeheftet haben, kommt in diesem Abzug nicht "
            "mehr vor - der Stand, gegen den Sie pruefen wollten, ist verschwunden (BRUCH)")
    if pin_kid and pin_kopf.get("key_id") != pin_kid:
        raise PruefungGescheitert(
            f"Kopf {pin['kopf_nr']} war mit {pin_kid} signiert, liegt hier aber mit "
            f"{pin_kopf.get('key_id')} vor - derselbe Stand, ein anderer Schluessel (BRUCH)")
    if pin_pub and pin_kopf.get("public_key") != pin_pub:
        raise PruefungGescheitert(
            f"Kopf {pin['kopf_nr']} traegt hier einen anderen public_key als angeheftet "
            f"({pin_kopf.get('public_key')} statt {pin_pub}) (BRUCH)")

    jetzt_kid = juengster.get("key_id")
    jetzt_pub = juengster.get("public_key")

    # 2. Gleicher Name, anderer Schluessel: der Tausch, der sich als Nicht-Tausch tarnt.
    if jetzt_kid == pin_kid:
        if pin_pub and jetzt_pub != pin_pub:
            raise PruefungGescheitert(
                f"der juengste Kopf nennt dieselbe key_id {jetzt_kid}, aber einen anderen "
                f"public_key als angeheftet ({jetzt_pub} statt {pin_pub}) - ein Tausch unter "
                "gleichem Namen (BRUCH)")
        # "Heute wieder derselbe" ist keine Aussage ueber die Strecke dazwischen.
        grund_gleich = _kopfkette_ab_pin(koepfe, str(pin.get("kopf_nr")), pin_kid, pin_kid)
        if grund_gleich:
            raise PruefungGescheitert(
                f"der juengste Kopf traegt zwar wieder {pin_kid}, aber die Kopf-Kette "
                f"widerspricht: {grund_gleich} (BRUCH)")
        return (f" Der Schluessel ist unveraendert gegenueber Ihrem angehefteten Stand "
                f"(key_id {jetzt_kid}), und zwar durchgehend ueber alle Koepfe seither.")

    # 3. Wechsel: erklaert oder Bruch.
    if key_history is None:
        raise PruefungGescheitert(
            f"der Schluessel hat gewechselt ({pin_kid} -> {jetzt_kid}), und ohne vorgelegte "
            "Schluesselhistorie (--key-history) ist der Wechsel nicht erklaerbar. Ein "
            "unerklaerter Wechsel ist ein Bruch; genau hier saehe eine Uebernahme wie eine "
            "Rotation aus (BRUCH)")
    fehlend = [k for k in (pin_kid, jetzt_kid) if k not in key_history]
    if fehlend:
        raise PruefungGescheitert(
            f"Schluesselwechsel {pin_kid} -> {jetzt_kid}, aber "
            + ", ".join(str(k) for k in fehlend)
            + " steht nicht in der vorgelegten Historie - unerklaerter Wechsel (BRUCH)")
    # Der Kern gegen die gefaelschte Historie: der Eintrag zu IHREM Schluessel
    # muss die Angabe tragen, die Sie selbst gesehen haben.
    if pin_pub and key_history[pin_kid].get("public_key") != pin_pub:
        raise PruefungGescheitert(
            f"die vorgelegte Historie fuehrt {pin_kid} mit einem anderen public_key, als Sie "
            f"angeheftet haben ({key_history[pin_kid].get('public_key')} statt {pin_pub}) - "
            "die Historie widerspricht Ihrer eigenen Beobachtung (BRUCH)")
    grund = _im_gueltigkeitsfenster(key_history[jetzt_kid], juengster.get("created_at"))
    if grund:
        raise PruefungGescheitert(
            f"Schluesselwechsel {pin_kid} -> {jetzt_kid}, aber der neue Schluessel {grund} "
            "(BRUCH)")
    alt = key_history[pin_kid]
    neu = key_history[jetzt_kid]
    # "Sein Gueltigkeitsfenster schliesst an das alte an" (#146, Umfang) - und
    # anschliessen kann nur, was ein ENDE hat. Genau hier liegt der Unterschied
    # zwischen einer Uebergabe und einer Uebernahme: wer einen Schluessel
    # ablegt, traegt sein valid_to nach. Eine Historie, die den alten
    # Schluessel offen laesst (valid_to null) und daneben einen zweiten
    # unterschreiben laesst, behauptet zwei gleichzeitig gueltige Schluessel -
    # das ist keine Rotation, das sind zwei Parteien.
    if not (isinstance(alt.get("valid_to"), str) and alt["valid_to"]):
        raise PruefungGescheitert(
            f"Schluesselwechsel {pin_kid} -> {jetzt_kid}, aber die Historie fuehrt {pin_kid} "
            "ohne valid_to, also weiter als gueltig. Ein Wechsel ohne abgelegten Vorgaenger "
            "ist keine erklaerte Rotation, sondern ein zweiter gleichzeitig gueltiger "
            "Schluessel (BRUCH)")
    if isinstance(juengster.get("created_at"), str) and juengster["created_at"] < alt["valid_to"]:
        raise PruefungGescheitert(
            f"Schluesselwechsel {pin_kid} -> {jetzt_kid}, obwohl {pin_kid} laut Historie noch "
            f"bis {alt['valid_to']} galt (BRUCH)")
    if not (isinstance(neu.get("valid_from"), str) and neu["valid_from"]):
        raise PruefungGescheitert(
            f"Schluesselwechsel {pin_kid} -> {jetzt_kid}, aber die Historie fuehrt {jetzt_kid} "
            "ohne valid_from - dann laesst sich nicht sagen, ob sein Fenster an das alte "
            "anschliesst (BRUCH)")
    if neu["valid_from"] < alt["valid_to"]:
        raise PruefungGescheitert(
            f"die Fenster ueberlappen: {jetzt_kid} gilt ab {neu['valid_from']}, {pin_kid} "
            f"noch bis {alt['valid_to']} - zwei gleichzeitig gueltige Schluessel sind keine "
            "Rotation (BRUCH)")
    grund_kette = _kopfkette_ab_pin(koepfe, str(pin.get("kopf_nr")), pin_kid, jetzt_kid)
    if grund_kette:
        raise PruefungGescheitert(
            f"Schluesselwechsel {pin_kid} -> {jetzt_kid} ist in der Kopf-Kette nicht "
            f"nachvollziehbar: {grund_kette} (BRUCH)")
    return (f" Der Schluessel hat seit Ihrem angehefteten Stand gewechselt "
            f"({pin_kid} -> {jetzt_kid}) - ERKLAERT: beide stehen in der vorgelegten Historie, "
            f"der Eintrag zu {pin_kid} traegt noch den public_key, den Sie angeheftet haben, "
            f"das Fenster von {pin_kid} endete {alt['valid_to']} und das von {jetzt_kid} "
            f"beginnt {neu['valid_from']} (schliesst an), und die Kopf-Kette zeigt genau "
            "einen Uebergang.")


def pin_aus_kopf(kopf: Dict[str, Any], quelle: str) -> Dict[str, Any]:
    """
    Der Teil eines Kopfes, den ein Beobachter aufbewahrt. Kein eigener
    Zeitstempel: dieser Verifier hat bewusst keine Uhr (er soll offline und
    reproduzierbar sein). Wann beobachtet wurde, haelt der Beobachter fest
    (verifier/phm_beobachter.py); was der Stand von SICH sagt, steht in
    stand_created_at.
    """
    return {
        "paket_typ": PIN_TYPE,
        "paket_version": PIN_VERSION,
        "quelle": quelle,
        "stand_created_at": kopf.get("created_at"),
        "kopf_nr": kopf["kopf_nr"],
        "kopf_hash": kopf["kopf_hash"],
        "tree_size": kopf["tree_size"],
        "root_hash": kopf["root_hash"],
        "key_id": kopf.get("key_id"),
        "public_key": kopf.get("public_key"),
    }


# --------------------------------------------- Anheften (E20, #154, #354)
#
# EINE Umsetzung fuer beide Werkzeuge. Der Beobachter (phm_beobachter.py)
# laedt sie aus dieser Datei, statt eine eigene zu fuehren. Bis E20 gab es
# zwei: der Beobachter schrieb seinen Pin write-once und erkannte die
# Gedaechtnisluecke, --anheften hier beschrieb die Datei an Ort und Stelle,
# scheiterte an der Ablage des Beobachters (PermissionError an 0444) und
# kannte die Luecke nicht. Zwei Umsetzungen derselben Sicherheitslogik
# laufen auseinander; deshalb liegt sie hier, wo beide sie erreichen: der
# Verifier ist eigenstaendig (wird in Werk-Pakete kopiert, importiert
# nichts), der Beobachter braucht ihn ohnehin neben sich.
#
# Vorbild ist das Pinning der Certificate Transparency (RFC 6962/9162): der
# Pruefer haelt seinen eigenen Stand, und der ist nur so viel wert wie seine
# Unversehrtheit.

PIN_MODUS = 0o444
# Das Protokoll der Anheftungen. Pin und Protokoll zusammen sind das
# Gedaechtnis; die Kombination "Protokoll ja, Pin nein" ist die, die auffallen
# muss (#154). Es liegt immer NEBEN dem Pin, und jede Zeile nennt den Pin, zu
# dem sie gehoert (Feld "pin", Dateiname): mehrere Pins in einem Ordner teilen
# sich die Datei, aber nicht das Gedaechtnis.
BEOBACHTUNGEN_DATEI = "beobachtungen.jsonl"
# Zeilen von vor dem Feld "pin" schrieb nur der Beobachter, und der heftet
# immer unter diesem Namen an. Sie gelten deshalb fuer genau diesen Pin.
PROTOKOLL_PIN_VORGABE = "angehefteter_stand.json"


def beobachtungen_neben(pin: str) -> str:
    """Pfad des Protokolls, das zum Pin gehoert: derselbe Ordner."""
    return os.path.join(os.path.dirname(os.path.abspath(pin)), BEOBACHTUNGEN_DATEI)


def _ordner_fsync(ordner: str) -> None:
    """Den Ordnereintrag selbst auf die Platte bringen (nach os.replace). Unter
    POSIX laesst sich ein Ordner oeffnen und fsyncen; unter Windows nicht, dort
    bleibt es beim fsync der Datei."""
    if os.name != "posix":
        return
    fd = os.open(ordner, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def schreibe_pin(pin: str, inhalt: Dict[str, Any]) -> None:
    """
    Schreibt den angehefteten Stand write-once wie die Koepfe (#154, E20).

    Neben die Datei schreiben (exklusiv, mkstemp), auf die Platte bringen
    (fsync), auf 0444 setzen, dann an ihre Stelle schieben (os.replace) und
    den Ordner fsyncen. Ein Pin, den man beschreiben kann, ist ein Pin, den
    man auch still umschreiben kann; ein Austausch braucht Schreibrecht am
    ORDNER, und der Wechsel ist atomar - es gibt keinen Zeitpunkt, an dem ein
    halber Stand angeheftet waere, auch nicht nach einem Stromausfall.

    Der Unterschied zu den Koepfen (O_EXCL + 0444, jeder unter eigenem Namen):
    ein Kopf kommt hinzu, der Pin rueckt weiter. Ersetzen ist deshalb gewollt,
    Beschreiben nicht.
    """
    ordner = os.path.dirname(os.path.abspath(pin))
    fd, neben = tempfile.mkstemp(dir=ordner, prefix=os.path.basename(pin) + ".neu")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(inhalt, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(neben, PIN_MODUS)
        os.replace(neben, pin)
    except BaseException:
        # Kein halber Stand und kein Rest: was nicht angeheftet wurde, bleibt
        # auch nicht liegen.
        if os.path.exists(neben):
            os.chmod(neben, 0o600)
            os.remove(neben)
        raise
    _ordner_fsync(ordner)


def protokolliere_anheftung(protokoll: str, eintrag: Dict[str, Any]) -> None:
    """Eine Zeile ans Protokoll haengen und auf die Platte bringen."""
    with open(protokoll, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(eintrag, ensure_ascii=False, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def hefte_an(pin: str, inhalt: Dict[str, Any], eintrag: Dict[str, Any]) -> None:
    """
    Der ganze Anheftvorgang, fuer Verifier und Beobachter derselbe: erst der
    Pin, dann die Protokollzeile. Umgekehrt entstuende bei einem Abbruch
    dazwischen genau die Lage, die gedaechtnisluecke() als Bruch meldet.
    """
    schreibe_pin(pin, inhalt)
    zeile = dict(eintrag)
    zeile["pin"] = os.path.basename(pin)
    protokolliere_anheftung(beobachtungen_neben(pin), zeile)


def _protokoll_lage(protokoll: str, pin_name: str) -> Tuple[int, Optional[Dict[str, Any]]]:
    """Wie viele Laeufe das Protokoll fuer DIESEN Pin ausweist und was dessen
    letzte Zeile sagt. Eine Zeile ohne "pin" gilt fuer PROTOKOLL_PIN_VORGABE.
    Eine unlesbare Zeile laesst sich keinem Pin zuordnen und zaehlt deshalb fuer
    jeden: im Zweifel ein Bruch zu viel, nie ein stiller Neuanfang."""
    zeilen = 0
    letzte: Optional[Dict[str, Any]] = None
    try:
        with open(protokoll, "r", encoding="utf-8") as fh:
            for zeile in fh:
                if not zeile.strip():
                    continue
                try:
                    eintrag = json.loads(zeile)
                except ValueError:
                    eintrag = None
                if isinstance(eintrag, dict):
                    if eintrag.get("pin", PROTOKOLL_PIN_VORGABE) != pin_name:
                        continue
                    letzte = eintrag
                else:
                    letzte = None
                zeilen += 1
    except (OSError, UnicodeDecodeError):
        pass
    return zeilen, letzte


def gedaechtnisluecke(pin: str) -> Optional[Dict[str, Any]]:
    """
    Prueft die eine Kombination, die kein Anfangszustand sein kann (#154):
    der angeheftete Stand fehlt, das Protokoll daneben weist fruehere
    Anheftungen GENAU DIESES Pins aus (Zeilen anderer Pins im selben Ordner
    zaehlen nicht).

    Das ist die Angriffsform, gegen die das Verzeichnis gebaut ist, angewandt
    auf den Pruefer selbst: wer den Pin loescht, loescht das Gedaechtnis, und
    der naechste Lauf bestaetigt jeden vorgefundenen Stand als Anfangsstand.
    Es braucht keinen Angreifer, ein aufgeraeumtes Verzeichnis genuegt. Der
    echte Erstlauf ist davon nicht betroffen: der hat beides nicht.

    Liefert die Begruendung als Ergebnis-Teil, oder None, wenn alles in
    Ordnung ist.
    """
    protokoll = beobachtungen_neben(pin)
    if os.path.isfile(pin) or not os.path.exists(protokoll):
        return None
    zeilen, letzte = _protokoll_lage(protokoll, os.path.basename(pin))
    if zeilen == 0:
        # Das Protokoll gehoert anderen Pins im selben Ordner; fuer DIESEN ist
        # es ein echter Erstlauf.
        return None
    return {
        "passed": False,
        "bruch": True,
        "art": "gedaechtnisluecke",
        "grund": (
            f"Der angeheftete Stand fehlt ({pin}), aber {protokoll} weist "
            f"{zeilen} fruehere(n) Lauf/Laeufe aus. 'Schon beobachtet, aber nicht "
            "mehr wissen was' ist kein Anfangszustand: ohne Pin bleibt V5 aus, "
            "und der Lauf wuerde jeden vorgefundenen Stand als ersten anheften "
            "- damit waere die Vorgeschichte eingeebnet, gegen die diese Rolle "
            "gebaut ist. Der echte Erstlauf hat weder Pin noch Protokoll."
        ),
        "pin": pin,
        "beobachtungen": protokoll,
        "beobachtungen_zeilen": zeilen,
        "letzter_stand_laut_protokoll": letzte,
        "abhilfe": (
            "Den Pin aus der Sicherung zurueckholen. Ist er endgueltig weg, die "
            "Beobachtung BEWUSST neu beginnen: das Protokoll unter neuem Namen "
            "aufbewahren (z. B. beobachtungen_bis_<datum>.jsonl), damit der "
            "Neubeginn eine Spur hinterlaesst, statt eine zu loeschen. Beides "
            "ist Handarbeit; automatisch wird hier nichts fortgeschrieben."
        ),
    }


def verify_konsistenz_paket(
    paket: Any,
    public_key_hex: Optional[str] = None,
    key_history: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Prueft ein eigenstaendiges Konsistenz-Paket (zwei signierte KOEPFE +
    Pfad). Zwei Schritte, und der erste ist der Grund fuer Paketversion 2:

    K1 sagt, dass die beiden Staende von der Instanz stammen (Ed25519 ueber
    denselben Weg wie V4 im vollen Durchlauf), K2 sagt, dass sie
    vertraeglich sind. Version 1 hatte nur K2 und rechnete damit ueber
    Zahlen, die der Uebermittler frei setzen konnte: als Austauschformat
    zwischen zwei Beobachtern trug ein solches Paket nichts, weil B nicht
    unterscheiden konnte, ob der Stand von A stammt oder von der Instanz
    (#155).
    """
    checks: List[Dict[str, str]] = []
    if not isinstance(paket, dict) or paket.get("paket_typ") != KONSISTENZ_PAKET_TYPE:
        raise PaketFehler(f"Konsistenz-Paket: paket_typ {KONSISTENZ_PAKET_TYPE!r} erwartet")
    if paket.get("paket_version") != KONSISTENZ_PAKET_VERSION:
        raise PaketFehler(
            f"Konsistenz-Paket: paket_version {paket.get('paket_version')!r} wird von diesem "
            f"Verifier nicht getragen, nur {KONSISTENZ_PAKET_VERSION!r}. Version '1' trug "
            "statt der Koepfe einen unsignierten Ausweis und ist als Nachweis wertlos"
        )
    alt, neu = paket.get("alt") or {}, paket.get("neu") or {}

    # K1: Echtheit VOR Vertraeglichkeit. Ein Pfad, der ueber erfundene
    # Wurzeln aufgeht, ist ein korrekter Beweis fuer nichts.
    befunde: List[str] = []
    for wo, kopf in (("alt", alt), ("neu", neu)):
        try:
            verify_verzeichnis_kopf(kopf, public_key_hex, key_history)
        except PruefungGescheitert as e:
            befunde.append(f"Kopf '{wo}': {e}")
    if befunde:
        checks.append(_check("K1. Echtheit der beiden Staende (Ed25519)", NICHT_BESTANDEN,
                             "; ".join(befunde)))
    else:
        checks.append(
            _check(
                "K1. Echtheit der beiden Staende (Ed25519)", BESTANDEN,
                f"beide Koepfe liegen im Original vor und sind signiert: Kopf "
                f"{alt.get('kopf_nr')} ({alt.get('key_id')}, created_at "
                f"{alt.get('created_at')}) und Kopf {neu.get('kopf_nr')} "
                f"({neu.get('key_id')}, created_at {neu.get('created_at')}); kopf_hash "
                "bindet Inhalt UND Signatur. Wer dieses Paket weitergereicht hat, spielt "
                "fuer die Aussage keine Rolle. Geprueft wurden die Signaturen "
                f"{_schluessel_herkunft(public_key_hex, key_history)}.",
            )
        )

    # K2: Vertraeglichkeit - Groesse und Wurzel kommen aus den SIGNIERTEN
    # Koepfen, nicht aus frei gesetzten Feldern daneben.
    try:
        if int(str(alt.get("kopf_nr"))) > int(str(neu.get("kopf_nr"))):
            raise PruefungGescheitert(
                f"'alt' ist Kopf {alt.get('kopf_nr')}, 'neu' ist Kopf {neu.get('kopf_nr')} - "
                "als frueherer Stand taugt der spaetere nicht"
            )
        verify_merkle_consistency(
            int(alt.get("tree_size")),
            str(alt.get("root_hash")),
            int(neu.get("tree_size")),
            str(neu.get("root_hash")),
            paket.get("pfad") or [],
        )
        checks.append(
            _check(
                "K2. Konsistenz zweier Staende (RFC 6962)",
                BESTANDEN,
                f"Stand {alt.get('kopf_nr')} ({alt.get('tree_size')} Zeilen, Wurzel "
                f"{alt.get('root_hash')}) ist unveraendertes Anfangsstueck von Stand "
                f"{neu.get('kopf_nr')} ({neu.get('tree_size')} Zeilen), belegt ueber "
                f"{len(paket.get('pfad') or [])} Knoten-Hashes.",
            )
        )
    except PruefungGescheitert as e:  # erbt von ValueError, muss zuerst stehen
        checks.append(_check("K2. Konsistenz zweier Staende (RFC 6962)", NICHT_BESTANDEN, str(e)))
    except (TypeError, ValueError) as e:
        checks.append(_check("K2. Konsistenz zweier Staende (RFC 6962)", NICHT_BESTANDEN,
                             f"Paket unvollstaendig oder falsch getippt: {e}"))

    failed = [c for c in checks if c["ergebnis"] == NICHT_BESTANDEN]
    k1_gefallen = any(c["pruefung"].startswith("K1") for c in failed)
    if k1_gefallen:
        verdict = (
            "NICHT BESTANDEN: mindestens einer der beiden Koepfe ist nicht echt. Ueber "
            "einen manipulierten Kopf sagt der Konsistenzpfad nichts - das Paket ist als "
            "Nachweis unbrauchbar, gleich was K2 meldet."
        )
    elif failed:
        verdict = (
            "NICHT BESTANDEN: beide Koepfe sind echt signiert, aber die Staende sind "
            "nicht vertraeglich. Das ist ein BRUCH und gehoert gemeldet."
        )
    else:
        urheber = (
            "beide Staende sind mit einem Schluessel aus der vorgelegten Historie signiert"
            if key_history is not None else
            "beide Staende sind signiert und nennen ihren Urheber - OHNE --key-history "
            "bleibt aber unbelegt, dass es der freigegebene Schluessel der Instanz ist "
            "(K1)"
        )
        verdict = (
            f"BESTANDEN: {urheber}, und der spaetere Stand enthaelt den frueheren "
            "unveraendert. Was dieses Paket NICHT sagt: ob die beiden Koepfe in der "
            "veroeffentlichten Kopf-Kette aufeinander folgen, und ob es zwischen ihnen "
            "weitere Staende gab - das sieht nur, wer den vollen Abzug prueft."
        )
    return {"checks": checks, "verdict": verdict, "passed": not failed}


def anker_deckung_befunde(manifest_nrn: Any, verankert: set, nur_erneuert: set) -> List[str]:
    """Deckungsregel der Archiv-Wurzeln, Zweitimplementierung (nicht importiert).

    Referenz und Vorbild: anker_deckung_befunde in backend/src/archiv/wurzel.py
    (#195, Nachzug #235). JEDES Manifest braucht einen eigenen geprueften
    'direkt'-Anker; das juengste darf zwischen Wurzel- und Ankerlauf offen
    sein. Ein Manifest, das nur einen Erneuerungs-Anker traegt, bekommt eine
    eigene Meldung. Die Befundtexte sind mit denen dort wortgleich; ein Test
    (test_anker_deckung.py) haelt beide Implementierungen auf denselben
    Faellen gegeneinander. Importieren darf der Verifier die Funktion nicht:
    er laeuft als einzelne Datei ohne unseren Code (Issue #29).
    """
    alle = set(manifest_nrn)
    if not alle:
        return []
    juengste = max(alle)
    fehler: List[str] = []
    for nr in sorted(alle - verankert):
        if nr == juengste:
            continue
        if nr in nur_erneuert:
            fehler.append(
                f"Manifest {nr}: nur Erneuerungs-Anker, kein 'direkt'-Anker - "
                "die fruehe Zeitaussage fehlt, bezeugt ist nur der spaetere "
                "Zeitpunkt"
            )
        else:
            fehler.append(
                f"Manifest {nr}: ohne jeden externen Anker - nur innerhalb "
                "unserer Reichweite bezeugt"
            )
    return fehler


def verify_verzeichnis(
    daten: Dict[str, Any],
    pin: Optional[Dict[str, Any]] = None,
    public_key_hex: Optional[str] = None,
    trusted_cert_der: Optional[Any] = None,
    key_history: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Faehrt die Pruefschritte V1 bis V7 ueber einem Verzeichnis-Abzug."""
    checks: List[Dict[str, str]] = []
    rohe: List[bytes] = daten["rohe_zeilen"]
    koepfe: List[Dict[str, Any]] = daten["koepfe"]
    blatt_hashes = [hashlib.sha256(z).hexdigest() for z in rohe]
    zeilen: List[Optional[Dict[str, Any]]] = []
    bruch = False

    # V1: Zeilenkette (ohne Baum, ohne Schluessel nachvollziehbar)
    befunde: List[str] = []
    prev = EMPTY_TREE_ROOT
    for i, roh in enumerate(rohe, start=1):
        try:
            z = json.loads(roh)
            if not isinstance(z, dict):
                raise ValueError("Objekt erwartet")
        except ValueError as e:
            befunde.append(f"Zeile {i}: kein JSON-Objekt ({e})")
            zeilen.append(None)
            prev = hashlib.sha256(roh).hexdigest()
            continue
        zeilen.append(z)
        if kanonische_zeile(z) != roh:
            befunde.append(f"Zeile {i}: nicht in kanonischer Form (nachtraeglich umgeschrieben?)")
        if z.get("nr") != i:
            befunde.append(f"Zeile {i}: traegt nr {z.get('nr')!r}")
        if z.get("typ") not in _ZEILE_FELDER:
            befunde.append(f"Zeile {i}: unbekannter typ {z.get('typ')!r}")
        if z.get("prev") != prev:
            befunde.append(f"Zeile {i}: prev passt nicht zur Vorgaengerzeile (entfernt oder umsortiert?)")
        prev = hashlib.sha256(roh).hexdigest()
    if befunde:
        checks.append(_check("V1. Zeilenkette (append-only)", NICHT_BESTANDEN, "; ".join(befunde[:8])))
    else:
        checks.append(
            _check(
                "V1. Zeilenkette (append-only)", BESTANDEN,
                f"{len(rohe)} Zeilen, jede in kanonischer Form, jede mit dem SHA-256 ihrer "
                "Vorgaengerzeile verkettet (Genesis = SHA-256 der leeren Eingabe). Entfernen, "
                "Einfuegen und Umsortieren faellt hier auf, ohne Baum und ohne Schluessel.",
            )
        )

    # V2: Wurzel-Zeilen - die Wochen-Manifeste, im Verzeichnis selbst pruefbar
    befunde = []
    manifeste: Dict[int, Dict[str, Any]] = {}
    prev_hash = EMPTY_TREE_ROOT
    letzte_nr = 0
    letzte_groesse = 0
    letzte_key_id: Optional[str] = None
    for i, z in enumerate(zeilen, start=1):
        if not z or z.get("typ") != "wurzel":
            continue
        manifest = z.get("manifest")
        if not isinstance(manifest, dict):
            befunde.append(f"Zeile {i}: manifest fehlt")
            continue
        try:
            verify_archive_manifest(manifest, public_key_hex, key_history)
        except PruefungGescheitert as e:
            befunde.append(f"Zeile {i}: {e}")
            continue
        nr = int(manifest["manifest_nr"])
        # Derselbe Rotationstest wie bei den Koepfen (V4). Er fehlte hier
        # ganz: gemessen am selben Abzug meldete V4 einen offenen Vorgaenger
        # und V2 blieb bestanden - die Manifeste trugen dieselbe Uebernahme
        # ungeprueft.
        if key_history is not None and letzte_key_id is not None:
            grund = _rotation_erklaert(letzte_key_id, manifest.get("key_id"),
                                       key_history, manifest.get("created_at"))
            if grund:
                befunde.append(f"Zeile {i} (Manifest {nr}): {grund}")
        letzte_key_id = manifest.get("key_id")
        manifeste[nr] = manifest
        if nr != letzte_nr + 1:
            befunde.append(f"Zeile {i}: manifest_nr {nr} folgt nicht auf {letzte_nr} (Luecke)")
        if manifest["prev_manifest_hash"] != prev_hash:
            befunde.append(f"Zeile {i}: Manifest-Kette gebrochen")
        groesse = int(manifest["tree_size"])
        if letzte_nr and groesse <= letzte_groesse:
            befunde.append(f"Zeile {i}: Archiv-Baumgroesse {groesse} nicht groesser als {letzte_groesse}")
        prev_hash, letzte_nr, letzte_groesse = manifest["manifest_hash"], nr, groesse
    if befunde:
        checks.append(_check("V2. Wochen-Manifeste im Verzeichnis (Ed25519)", NICHT_BESTANDEN,
                             "; ".join(befunde[:8])))
    elif not manifeste:
        checks.append(_check("V2. Wochen-Manifeste im Verzeichnis (Ed25519)", UEBERSPRUNGEN,
                             "das Verzeichnis enthaelt keine Wurzel-Zeile"))
    else:
        herkunft = _schluessel_herkunft(
            public_key_hex, key_history,
            _fenster_lage(list(manifeste.values()), key_history)
            if key_history is not None else None)
        checks.append(
            _check(
                "V2. Wochen-Manifeste im Verzeichnis (Ed25519)", BESTANDEN,
                f"{len(manifeste)} Manifest(e), lueckenlose Nummern, Kette der prev_manifest_hash "
                f"geschlossen, Archiv-Baum waechst monoton; Signaturen {herkunft} geprueft.",
            )
        )

    # V3: Anker-Zeilen - Zeitpunkt der Wurzeln, extern bezeugt
    befunde = []
    geprueft = 0
    zertifikat_offen = 0
    verankert: set = set()
    nur_erneuert: set = set()
    # Z2-F1 (#145): das Token bezeugt die Wurzel, nicht die Entstehungszeit,
    # die das Manifest daneben behauptet. Ohne den Vergleich besteht ein
    # heute gebautes Manifest mit created_at von 2020 diesen Schritt.
    zeitbefunde: List[str] = []
    for i, z in enumerate(zeilen, start=1):
        if not z or z.get("typ") != "anker":
            continue
        try:
            manifest = manifeste.get(int(str(z.get("manifest_nr"))))
        except ValueError:
            manifest = None
        if manifest is None:
            befunde.append(f"Zeile {i}: bezieht sich auf Manifest {z.get('manifest_nr')!r}, "
                           "das im Verzeichnis nicht steht")
            continue
        a = z.get("anker") or {}
        try:
            if z.get("root_hash") != manifest["root_hash"]:
                raise PruefungGescheitert("root_hash passt nicht zum veroeffentlichten Manifest")
            try:
                token_der = base64.b64decode(str(a.get("token_b64", "")), validate=True)
            except (ValueError, binascii.Error):
                raise PruefungGescheitert("anker.token_b64: keine gueltige Base64-Kodierung")
            if a.get("token_sha256") != hashlib.sha256(token_der).hexdigest():
                raise PruefungGescheitert("anker.token_sha256 passt nicht zu den Token-Bytes")
            info = verify_timestamp_token(token_der, trusted_cert_der)
            if info["hash_algo_oid"] != OID_SHA256:
                raise PruefungGescheitert("messageImprint: Algorithmus ist nicht SHA-256")
            if info["hashed_message"] != manifest["root_hash"]:
                raise PruefungGescheitert("das Token bezeugt einen anderen Hash als die Wurzel")
            if info["trusted_cert_match"] is None:
                zertifikat_offen += 1
            elif not info["trusted_cert_match"]:
                raise PruefungGescheitert("Signer-Zertifikat ist KEINES der vorgelegten")
            fehl, befund = _zeit_gegen_anker(
                manifest.get("created_at"), info["gen_time"],
                f"Manifest {manifest.get('manifest_nr')}: created_at")
            if fehl:
                raise PruefungGescheitert(fehl)
            if befund:
                zeitbefunde.append(befund)
            geprueft += 1
            # Nur ein 'direkt'-Anker deckt sein Manifest (#195/#235, wie
            # backend/src/archiv/wurzel.py anker_deckung_befunde). Bis
            # ap14 zaehlte hier JEDER gepruefte Anker, auch ein
            # Erneuerungs-Anker - der Verifier urteilte damit milder als die
            # interne Pruefung ueber denselben Abzug. Eine Erneuerung bezeugt
            # den spaeteren Zeitpunkt, nicht den frueheren, und die fruehe
            # Zeitaussage ist das Beweisziel. Fehlt das Feld zweck, zaehlt
            # die Zeile wie dort NICHT als 'direkt'.
            if z.get("zweck") == "direkt":
                verankert.add(int(manifest["manifest_nr"]))
            else:
                nur_erneuert.add(int(manifest["manifest_nr"]))
        except PruefungGescheitert as e:
            befunde.append(f"Zeile {i} ({a.get('tsa_id')}): {e}")

    # Deckung, nicht nur Echtheit: Werners Vorgabe ist ein externer Anker JE
    # EINTRAG. Eine Wurzel ohne Anker ist innerhalb unserer Reichweite
    # bezeugt und sonst nirgends - und das faellt sonst niemandem auf, weil
    # eine geprueffte Anker-Zeile nichts ueber die fehlenden sagt. Die
    # juengste Wurzel darf zwischen Wurzel- und Anker-Lauf offen sein.
    juengste_wurzel = max(manifeste) if manifeste else None
    ohne_anker = sorted(nr for nr in manifeste if nr not in verankert)
    befunde.extend(anker_deckung_befunde(manifeste, verankert, nur_erneuert))
    zeittext = ("" if not zeitbefunde
                else " BEFUND zur Entstehungszeit: " + _gekuerzt(zeitbefunde) + ".")
    if befunde:
        checks.append(_check("V3. Externe Anker der Wurzeln (RFC 3161)", NICHT_BESTANDEN,
                             _gekuerzt(befunde, 8) + zeittext))
    elif not geprueft:
        checks.append(
            _check("V3. Externe Anker der Wurzeln (RFC 3161)", UEBERSPRUNGEN,
                   "keine Anker-Zeile im Verzeichnis: die Wurzeln sind dann nur innerhalb "
                   "unserer Reichweite bezeugt, ein ZEITPUNKT ist nicht belegt")
        )
    else:
        zusatz = (f" Bei {zertifikat_offen} Anker(n) wurde kein Vertrauenszertifikat vorgelegt "
                  "(--tsa-cert); wem das Signer-Zertifikat gehoert, stellt der Pruefer selbst fest."
                  ) if zertifikat_offen else ""
        offen = (f" Die juengste Wurzel (Manifest {juengste_wurzel}) traegt noch keinen "
                 "'direkt'-Anker - zwischen Wurzel- und Ankerlauf normal, dauerhaft ein Befund."
                 ) if ohne_anker else ""
        checks.append(
            _check("V3. Externe Anker der Wurzeln (RFC 3161)", BESTANDEN,
                   f"{geprueft} Token vollstaendig geprueft: messageImprint = veroeffentlichte "
                   f"Wurzel, TSA-Signatur ueber den signierten Attributen verifiziert; "
                   f"{len(verankert)} von {len(manifeste)} Wurzel(n) extern verankert "
                   "(als Deckung zaehlt nur ein 'direkt'-Anker). Die "
                   "behauptete Entstehungszeit (created_at) ist gegen die bezeugte gehalten."
                   f"{zusatz}{offen}{zeittext}")
        )

    # V4: Koepfe - die Staende des Verzeichnisses selbst
    befunde = []
    prev = EMPTY_TREE_ROOT
    letzte_groesse = 0
    juengster = koepfe[-1]
    for i, kopf in enumerate(koepfe, start=1):
        try:
            verify_verzeichnis_kopf(kopf, public_key_hex, key_history)
        except PruefungGescheitert as e:
            befunde.append(f"Kopf {i}: {e}")
            prev = kopf.get("kopf_hash") or prev
            continue
        if kopf["kopf_nr"] != str(i):
            befunde.append(f"Kopf {i}: kopf_nr {kopf['kopf_nr']} an Position {i}")
        if kopf["prev_kopf_hash"] != prev:
            befunde.append(f"Kopf {i}: Kette gebrochen (prev_kopf_hash passt nicht)")
        # Ein Schluesselwechsel MITTEN in der Kette muss erklaert sein: beide
        # key_ids in der Historie, und der neue Schluessel darf zum Zeitpunkt
        # des Kopfes schon gelten. Ohne diese Pruefung sieht eine Uebernahme
        # durch einen fremden Schluessel wie eine normale Rotation aus.
        if key_history is not None and i > 1:
            grund = _rotation_erklaert(
                koepfe[i - 2].get("key_id"), kopf.get("key_id"),
                key_history, kopf.get("created_at"))
            if grund:
                befunde.append(f"Kopf {i}: {grund}")
        groesse = int(kopf["tree_size"])
        if i > 1 and groesse <= letzte_groesse:
            befunde.append(f"Kopf {i}: tree_size {groesse} nicht groesser als {letzte_groesse}")
        if groesse > len(blatt_hashes):
            befunde.append(f"Kopf {i}: bezeugt {groesse} Zeilen, vorgelegt sind {len(blatt_hashes)}")
        elif merkle_tree_root(blatt_hashes[:groesse]) != kopf["root_hash"]:
            befunde.append(f"Kopf {i}: root_hash nicht aus den ersten {groesse} Zeilen nachrechenbar")
        prev, letzte_groesse = kopf["kopf_hash"], groesse
    if int(juengster.get("tree_size", "0")) == len(blatt_hashes) and \
            juengster.get("datei_pruefsumme") != "sha256:" + daten["datei_sha256"]:
        befunde.append("juengster Kopf: datei_pruefsumme passt nicht zur vorgelegten Datei")
    if befunde:
        bruch = True
        checks.append(_check("V4. Staende des Verzeichnisses (Kopf-Kette)", NICHT_BESTANDEN,
                             "; ".join(befunde[:8])))
    else:
        # Zeilen jenseits des juengsten Kopfes sind zwischen zwei Laeufen der
        # Normalfall - aber der Beobachter muss wissen, dass sie von keiner
        # Signatur gedeckt sind, sonst haelt er sie faelschlich fuer bezeugt.
        ungedeckt = len(blatt_hashes) - int(juengster.get("tree_size", "0"))
        nachsatz = (
            f" {ungedeckt} Zeile(n) liegen JENSEITS des juengsten Kopfes und sind damit "
            "von keiner Signatur gedeckt - zwischen zwei Laeufen normal, dauerhaft ein "
            "Hinweis, dass kein Kopf mehr gebildet wird." if ungedeckt > 0 else ""
        )
        checks.append(
            _check("V4. Staende des Verzeichnisses (Kopf-Kette)", BESTANDEN,
                   f"{len(koepfe)} Kopf/Koepfe, Kette geschlossen, Groesse monoton, und JEDE "
                   f"Wurzel aus den ersten tree_size Zeilen neu gerechnet. Juengster Stand: "
                   f"{juengster.get('tree_size')} Zeilen, Wurzel {juengster.get('root_hash')}, "
                   f"created_at {juengster.get('created_at')}. Signaturen "
                   f"{_schluessel_herkunft(public_key_hex, key_history, _fenster_lage(koepfe, key_history) if key_history is not None else None)} "
                   f"geprueft.{nachsatz}")
        )

    # V5: gegen den angehefteten frueheren Stand - der eigentliche Zweck
    if pin is None:
        checks.append(
            _check("V5. Vertraeglichkeit mit dem angehefteten Stand", UEBERSPRUNGEN,
                   "kein frueherer Stand vorgelegt (--pin). Ein einzelner Abzug kann nur in sich "
                   "stimmig sein; die Aussage des Verzeichnisses entsteht erst im Vergleich mit "
                   "dem, was frueher zu sehen war. Diesen Abzug mit --anheften aufbewahren.")
        )
    else:
        try:
            alte_groesse = int(pin["tree_size"])
            if alte_groesse > len(blatt_hashes):
                raise PruefungGescheitert(
                    f"der angeheftete Stand hat {alte_groesse} Zeilen, vorgelegt sind nur "
                    f"{len(blatt_hashes)} - das Verzeichnis ist geschrumpft (BRUCH)"
                )
            jetzige_wurzel = merkle_tree_root(blatt_hashes[:alte_groesse])
            if jetzige_wurzel != pin["root_hash"]:
                raise PruefungGescheitert(
                    f"die ersten {alte_groesse} Zeilen des vorgelegten Verzeichnisses ergeben die "
                    f"Wurzel {jetzige_wurzel}, angeheftet war {pin['root_hash']} - der frueher "
                    "veroeffentlichte Bestand wurde nachtraeglich veraendert (BRUCH)"
                )
            gleicher_kopf = next(
                (k for k in koepfe if k.get("kopf_nr") == pin["kopf_nr"]), None
            )
            if gleicher_kopf is not None and gleicher_kopf.get("kopf_hash") != pin["kopf_hash"]:
                raise PruefungGescheitert(
                    f"Kopf {pin['kopf_nr']} liegt hier mit einem anderen kopf_hash vor als "
                    "angeheftet - zwei verschiedene Geschichten desselben Standes (BRUCH)"
                )
            pfad = merkle_consistency_path(alte_groesse, blatt_hashes[:len(blatt_hashes)])
            verify_merkle_consistency(
                alte_groesse, pin["root_hash"], len(blatt_hashes),
                merkle_tree_root(blatt_hashes), pfad,
            )
            # Z2-F2 (#146): bis hierher wird die INHALTLICHE Fortschreibung
            # geprueft. Der Schluessel, den der Pin seit jeher mitfuehrt, wurde
            # nie angesehen - und er ist die einzige Angabe im ganzen Verfahren,
            # die nicht vom Herausgeber stammt.
            schluessel_satz = _pin_schluessel_gegen_abzug(
                pin, gleicher_kopf, juengster, key_history, koepfe)
            checks.append(
                _check("V5. Vertraeglichkeit mit dem angehefteten Stand", BESTANDEN,
                       f"der angeheftete Stand (Kopf {pin['kopf_nr']}, {alte_groesse} Zeilen, "
                       f"Wurzel {pin['root_hash']}, created_at {pin.get('stand_created_at')}) ist "
                       f"unveraendertes Anfangsstueck des vorgelegten ({len(blatt_hashes)} Zeilen); "
                       f"Konsistenznachweis nach RFC 6962 mit {len(pfad)} Knoten gegengerechnet."
                       f"{schluessel_satz}")
            )
        # PruefungGescheitert ERBT von ValueError - der spezielle Fall muss
        # zuerst stehen, sonst liest sich ein echter Bruch als Formfehler.
        except PruefungGescheitert as e:
            bruch = True
            checks.append(_check("V5. Vertraeglichkeit mit dem angehefteten Stand",
                                 NICHT_BESTANDEN, str(e)))
        except (KeyError, TypeError, ValueError) as e:
            bruch = True
            checks.append(_check("V5. Vertraeglichkeit mit dem angehefteten Stand",
                                 NICHT_BESTANDEN, f"Anheftung unbrauchbar: {e}"))

    # V6: Das Verzeichnis zeigt nichts als Wurzeln. Nachgesehen, nicht zugesichert.
    befunde = []
    for i, z in enumerate(zeilen, start=1):
        if not z:
            continue
        erlaubt = _ZEILE_FELDER.get(str(z.get("typ")))
        if erlaubt is None:
            continue
        fremd = [k for k in z if k not in erlaubt]
        if fremd:
            befunde.append(f"Zeile {i}: unbekannte Felder {', '.join(sorted(fremd))}")
        if z.get("typ") == "anker":
            fremd_a = [k for k in (z.get("anker") or {}) if k not in _ANKER_FELDER]
            if fremd_a:
                befunde.append(f"Zeile {i}: unbekannte Anker-Felder {', '.join(sorted(fremd_a))}")
        if z.get("typ") == "wurzel":
            manifest = z.get("manifest") or {}
            fremd_m = [k for k in manifest
                       if k not in _MANIFEST_SIGNED_FIELDS + ("signature", "manifest_hash", "public_key")]
            if fremd_m:
                befunde.append(f"Zeile {i}: unbekannte Manifest-Felder {', '.join(sorted(fremd_m))}")
    if befunde:
        checks.append(_check("V6. Datensparsamkeit des Verzeichnisses", NICHT_BESTANDEN,
                             "; ".join(befunde[:8])))
    else:
        checks.append(
            _check("V6. Datensparsamkeit des Verzeichnisses", BESTANDEN,
                   "nur Wurzeln, Prueffsummen, Zeitstempel-Token und Signaturen; keine Index-Zeile, "
                   "keine Dokument-Prueffsumme, kein Kunden- oder Portfoliobezug. Was dennoch "
                   "ablesbar ist (Anzahl der Archiv-Eintraege, Rhythmus der Laeufe), steht in "
                   "docs/VERZEICHNIS.md.")
        )

    # ---- V7: Anker AUF DIE KOEPFE --------------------------------------
    # V3 prueft die Anker der Archiv-Wurzeln, die als Zeilen im Verzeichnis
    # stehen. Die KOEPFE - die Staende, die ein Beobachter anheftet - haben
    # eigene Anker unter anker/. Die wurden nie gelesen (spiegeln kopiert sie
    # mit), also war nirgends belegt, dass der veroeffentlichte Stand einen
    # von aussen bezeugten Zeitpunkt hat. Ohne das kann der Fuehrende einen
    # Kopf zurueckdatieren.
    #
    # Deckung ueber ALLE Koepfe, nicht nur den juengsten (wie V3): eine
    # geprueffte Anker-Datei sagt nichts ueber die fehlenden. Und wie bei V3
    # darf der JUENGSTE Kopf zwischen Kopf- und Anker-Lauf noch offen sein -
    # sonst genuegt eine Stoerung bei der TSA, um bei jedem Beobachter Exit 1
    # auszuloesen.
    #
    # Und was der Anker NICHT leistet, seit Z2-F1 (#145) auch geprueft statt
    # nur behauptet: das Token bezeugt die Kopf-WURZEL zu einem Zeitpunkt, es
    # bezeugt nicht das created_at, das der Kopf daneben behauptet. Bis #145
    # stand hier "der veroeffentlichte Stand traegt einen Zeitpunkt, den nicht
    # wir bezeugen" - und ein heute gebauter Strang mit created_at von 2020,
    # heute frisch verankert, bestand diesen Schritt anstandslos. Der Leser
    # las 2020, bezeugt war heute. Seitdem laeuft der Vergleich in beide
    # Richtungen (_zeit_gegen_anker): weit davor ist der legitime Nachhol-Fall
    # und wird als BEFUND benannt, danach ist ein FEHLSCHLAG.
    lbl_v7 = "V7. Externe Anker auf die Koepfe (RFC 3161)"
    kopf_anker = daten.get("kopf_anker") or []
    juengster_nr = int(koepfe[-1]["kopf_nr"])
    kopf_nach_nr = {int(k["kopf_nr"]): k for k in koepfe}
    befunde_v7: List[str] = []
    zeitbefunde_v7: List[str] = []
    geprueft_v7 = 0
    # Wie V3: getrennt zaehlen, ob zu einem Token ein Vertrauenszertifikat
    # vorlag. Ohne das weiss der Verifier NICHT, wer das Token ausgestellt
    # hat - es koennte unseres sein (#158).
    zertifikat_offen_v7 = 0
    zertifikat_bezeugt_v7 = 0
    verankerte_koepfe: set = set()
    for eintrag in kopf_anker:
        rec = eintrag.get("anker") or {}
        try:
            try:
                nr = int(str(eintrag.get("kopf_nr")))
            except (TypeError, ValueError):
                raise PruefungGescheitert(
                    f"kopf_nr {eintrag.get('kopf_nr')!r} ist keine Nummer")
            kopf = kopf_nach_nr.get(nr)
            if kopf is None:
                raise PruefungGescheitert(
                    f"bezieht sich auf Kopf {nr}, der im Abzug nicht steht")
            # Kein Default auf die Kopf-Wurzel: ein fehlendes Feld waere sonst
            # stillschweigend richtig, und genau das soll auffallen.
            if "root_hash" not in eintrag:
                raise PruefungGescheitert("Feld root_hash fehlt")
            if str(eintrag["root_hash"]) != str(kopf["root_hash"]):
                raise PruefungGescheitert(
                    f"nennt die Wurzel {str(eintrag['root_hash'])[:16]}..., Kopf {nr} traegt "
                    f"{str(kopf['root_hash'])[:16]}...")
            try:
                token_der = base64.b64decode(str(rec.get("token_b64", "")), validate=True)
            except (ValueError, binascii.Error):
                raise PruefungGescheitert("anker.token_b64: keine gueltige Base64-Kodierung")
            if rec.get("token_sha256") != hashlib.sha256(token_der).hexdigest():
                raise PruefungGescheitert("anker.token_sha256 passt nicht zu den Token-Bytes")
            info = verify_timestamp_token(token_der, trusted_cert_der)
            if info["hash_algo_oid"] != OID_SHA256:
                raise PruefungGescheitert("messageImprint: Algorithmus ist nicht SHA-256")
            if info["hashed_message"] != kopf["root_hash"]:
                raise PruefungGescheitert(
                    "das Token bezeugt einen anderen Hash als die Kopf-Wurzel")
            fehl, befund = _zeit_gegen_anker(
                kopf.get("created_at"), info["gen_time"], "created_at")
            if fehl:
                raise PruefungGescheitert(fehl)
            if befund:
                zeitbefunde_v7.append(f"Kopf {nr}: {befund}")
            # Dieselbe Auswertung wie in V3, Zeile fuer Zeile: ein fremdes
            # Zertifikat ist ein Fehlschlag, ein fehlendes eine offene Frage.
            if info["trusted_cert_match"] is None:
                zertifikat_offen_v7 += 1
            elif not info["trusted_cert_match"]:
                raise PruefungGescheitert("Signer-Zertifikat ist KEINES der vorgelegten")
            else:
                zertifikat_bezeugt_v7 += 1
            geprueft_v7 += 1
            verankerte_koepfe.add(nr)
        except PruefungGescheitert as e:
            befunde_v7.append(f"Kopf {eintrag.get('kopf_nr')} ({rec.get('tsa_id') or 'Anker'}): {e}")

    # Fehlt anker/ GANZ, ist das ein anderer Fall als eine Luecke zwischen
    # vorhandenen Ankern: dann wurde nie verankert, und das wird benannt statt
    # als Deckungsluecke gemeldet.
    ohne_anker_v7 = sorted(nr for nr in kopf_nach_nr if nr not in verankerte_koepfe)
    # Der juengste Kopf darf zwischen Kopf- und Anker-Lauf offen sein.
    dauerhaft_offen_v7 = [nr for nr in ohne_anker_v7 if nr != juengster_nr]
    if dauerhaft_offen_v7:
        befunde_v7.append(
            "Kopf/Koepfe ohne jeden externen Anker: "
            + ", ".join(str(nr) for nr in dauerhaft_offen_v7)
            + " - nur innerhalb unserer Reichweite bezeugt, ein Zeitpunkt ist dafuer nicht belegt")

    if not kopf_anker:
        checks.append(_check(
            lbl_v7, UEBERSPRUNGEN,
            "kein anker/-Verzeichnis im Abzug: die veroeffentlichten Koepfe sind dann nur "
            "innerhalb unserer Reichweite bezeugt. Wer das Verzeichnis fuehrt, koennte einen "
            "Kopf zurueckdatieren, ohne dass es hier auffiele."))
    else:
        zeittext_v7 = ("" if not zeitbefunde_v7
                       else " BEFUND zur Entstehungszeit: "
                            + _gekuerzt(zeitbefunde_v7) + ".")
        if befunde_v7:
            checks.append(_check(lbl_v7, NICHT_BESTANDEN,
                                 "; ".join(befunde_v7[:8]) + zeittext_v7))
        else:
            nachlauf = (f"; Kopf {juengster_nr} ist noch ohne Anker, das ist zwischen Kopf- und "
                        "Anker-Lauf zulaessig" if juengster_nr in ohne_anker_v7 else "")
            # Der Satz ist das Produkt. "Einen Zeitpunkt, den nicht wir bezeugen"
            # stand hier unbedingt - auch dann, wenn gar kein Vertrauenszertifikat
            # vorlag und der Verifier ueber den Aussteller nichts wusste. Bei einem
            # selbstsignierten Signer-Zertifikat ist die Aussage schlicht falsch,
            # und genau dieser Fall war der einzige gruene Test (#158). V3 hat es
            # von Anfang an bedingt formuliert; jetzt sagen beide Schritte
            # dasselbe ueber dieselbe Tatsache.
            #
            # Zwei Faelle, nicht drei: --tsa-cert gilt fuer den ganzen Lauf, also
            # ist trusted_cert_match entweder bei JEDEM Token None oder bei
            # keinem. Ein gemischter Zweig waere nie erreichbar und damit
            # ungetestet - er steht deshalb nicht da.
            if zertifikat_offen_v7:
                aussage = (
                    f" Fuer alle {zertifikat_offen_v7} Token wurde KEIN Vertrauenszertifikat "
                    "vorgelegt (--tsa-cert): geprueft ist die Signatur gegen das IM TOKEN "
                    "mitgefuehrte Zertifikat. Wem dieses Zertifikat gehoert, stellt der Pruefer "
                    "selbst fest - es koennte auch unseres sein. Dass der Zeitpunkt von AUSSEN "
                    "bezeugt ist, steht damit hier NICHT fest.")
            else:
                aussage = (
                    f" Bei allen {zertifikat_bezeugt_v7} Token ist das Signer-Zertifikat eines "
                    "der vorgelegten (--tsa-cert): der veroeffentlichte Stand traegt damit einen "
                    "Zeitpunkt, den nicht wir bezeugen.")
            # Unabhaengig vom Zertifikat gilt seit #145: das created_at des Kopfes
            # ist gegen die bezeugte Zeit gehalten. Die Aussage haengt an der
            # Rechnung, nicht am Aussteller, und faellt deshalb nicht in die
            # Fallunterscheidung darueber.
            checks.append(_check(
                lbl_v7, BESTANDEN,
                f"{geprueft_v7} Token auf {len(verankerte_koepfe)} von {len(kopf_nach_nr)} Koepfen "
                "geprueft: messageImprint gleich der jeweiligen Kopf-Wurzel, Token-Signatur "
                f"gueltig{nachlauf}.{aussage} Das created_at, das der Kopf daneben behauptet, "
                f"ist gegen den bezeugten Zeitpunkt gehalten.{zeittext_v7}"))

    failed = [c for c in checks if c["ergebnis"] == NICHT_BESTANDEN]
    skipped = [c for c in checks if c["ergebnis"] == UEBERSPRUNGEN]
    if failed:
        verdict = (
            "NICHT BESTANDEN: mindestens eine Pruefung ist gescheitert."
            + (" Das ist ein BRUCH und gehoert gemeldet - die Belege dafuer sind dieser Abzug "
               "und der angeheftete Stand; beide aufbewahren." if bruch else "")
        )
    else:
        verdict = "BESTANDEN im Umfang der durchgefuehrten Pruefungen."
        if skipped:
            verdict += " Uebersprungen (nicht geprueft): " + "; ".join(c["pruefung"] for c in skipped) + "."
        verdict += (
            " Belegt ist, dass der veroeffentlichte Bestand nachtraeglich nicht veraendert wurde. "
            "NICHT belegt ist VOLLSTAENDIGKEIT: ein Dokument, das nie archiviert und nie "
            "veroeffentlicht wurde, fehlt hier unbemerkt. Das Verzeichnis zeigt, dass alle "
            "dieselbe Geschichte sehen, nicht dass die Geschichte alles enthaelt."
        )
    return {
        "checks": checks,
        "verdict": verdict,
        "passed": not failed,
        "bruch": bruch,
        "zeilen": len(rohe),
        "koepfe": len(koepfe),
        "kopf_version": KOPF_VERSION,
        "neuer_pin": pin_aus_kopf(juengster, daten["datei"]),
    }


# ===========================================================================
# Teil 8: CLI
# ===========================================================================

def _load_public_key(args: argparse.Namespace) -> Optional[str]:
    raw = None
    if args.public_key:
        raw = args.public_key.strip()
    elif args.public_key_file:
        try:
            with open(args.public_key_file, "r", encoding="ascii") as fh:
                raw = fh.read().strip()
        except OSError as e:
            raise PaketFehler(f"Schluesseldatei nicht lesbar: {e}")
    if raw is None:
        return None
    if not re.match(r"^[0-9a-fA-F]{64}$", raw):
        raise PaketFehler("oeffentlicher Schluessel: 32 Byte Hex (64 Zeichen) erwartet")
    return raw.lower()


def _ist_archiv_nachweis(path: str) -> bool:
    """Erkennt den zweiten Eingabetyp am package_type, ohne ihn schon zu pruefen."""
    return _json_typ(path, "package_type") == ARCHIVE_PROOF_TYPE


def _json_typ(path: str, feld: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            geladen = json.load(fh)
    except (OSError, ValueError):
        return None
    return geladen.get(feld) if isinstance(geladen, dict) else None


def _ist_verzeichnis(path: str) -> bool:
    """Dritter Eingabetyp: ein Verzeichnis-Abzug (Ordner oder die jsonl-Datei)."""
    if os.path.isdir(path):
        return os.path.isfile(os.path.join(path, VERZEICHNIS_DATEI))
    return os.path.basename(path) == VERZEICHNIS_DATEI


# Welcher Eingabetyp WERTET welche Option aus (Z2-F11, #162). Die Liste ist
# die einzige Stelle, an der das steht - eine neue Option kostet eine Zeile,
# und wer sie hier vergisst, bekommt einen Abbruch statt eines stillen
# Ergebnisses.
#
# Der Anlass: --key-history wurde nur im Verzeichnis-Zweig durchgereicht,
# Archiv-Nachweis und Konsistenz-Paket schluckten sie wortlos. Eine still
# geschluckte Option ist schlimmer als eine fehlende - der Aufrufer glaubt,
# er habe die Historie vorgelegt, und liest ein Ergebnis, das ohne sie
# entstanden ist. Fuer --pin/--anheften/--dokument gab es die Wache schon,
# nur eben von Hand und deshalb unvollstaendig.
#
# Ausgabeoptionen (--json) stehen nicht drin: sie steuern die Darstellung,
# nicht die Pruefung, und gelten fuer alle Typen.
#
# ABGRENZUNG zu #161 (Vorrang der Historie): diese Wache fragt, ob ein
# EINGABETYP eine Option ueberhaupt auswertet - nicht, ob eine KOMBINATION
# zweier Optionen die eine unangewandt laesst. Dass --public-key neben
# --key-history unangewandt bleibt, ist dort entschieden und wird dort
# angesagt (Hinweis beim Aufruf, Ausweis im Bericht); es ist kein Schweigen
# und deshalb kein Fall fuer diesen Abbruch. Die beiden Regeln greifen
# ineinander, sie widersprechen sich nicht.
AUSGEWERTETE_OPTIONEN: Dict[str, set] = {
    "verzeichnis": {"public_key", "public_key_file", "key_history", "tsa_cert",
                    "pin", "anheften"},
    # Das Konsistenz-Paket prueft heute nur die Rechnung zwischen zwei
    # Staenden und wertet KEINEN Schluessel aus - auch --public-key nicht.
    # Mit den signierten Koepfen im Original (#155) wird das aufloesbar; bis
    # dahin ist der Abbruch die ehrliche Antwort.
    "konsistenz": set(),
    "archiv_nachweis": {"public_key", "public_key_file", "key_history", "tsa_cert",
                        "dokument"},
    "siegel_paket": {"public_key", "public_key_file", "key_history", "tsa_cert",
                     "archiv_public_key"},
}

_OPTIONSNAMEN = {
    "public_key": "--public-key", "public_key_file": "--public-key-file",
    "key_history": "--key-history", "tsa_cert": "--tsa-cert",
    "archiv_public_key": "--archiv-public-key", "dokument": "--dokument",
    "pin": "--pin", "anheften": "--anheften",
}

_TYPBEZEICHNUNG = {
    "verzeichnis": "ein Verzeichnis-Abzug",
    "konsistenz": "ein Konsistenz-Paket",
    "archiv_nachweis": "ein Archiv-Zugehoerigkeitsnachweis",
    "siegel_paket": "ein Siegel-Paket",
}


def _pruefe_optionen(eingabetyp: str, args: Any) -> None:
    """Bricht ab, wenn eine gesetzte Option von diesem Eingabetyp nicht
    ausgewertet wird. Schweigen waere die schlechtere Antwort."""
    ausgewertet = AUSGEWERTETE_OPTIONEN[eingabetyp]
    gesetzt_aber_taub = [
        _OPTIONSNAMEN[feld] for feld in _OPTIONSNAMEN
        # getattr OHNE Default (#160): der Feldname kommt aus der Tabelle, ein
        # direkter args.x-Zugriff ist hier nicht schreibbar. Ein dritter
        # Parameter waere aber dasselbe stille Auffangnetz, gegen das #160
        # gebaut ist - wer eine Option umbenennt und _OPTIONSNAMEN vergisst,
        # bekaeme dann ein None und dieser Waechter schwiege ueber genau die
        # Option, die er bewachen soll.
        if feld not in ausgewertet and getattr(args, feld)
    ]
    if gesetzt_aber_taub:
        raise PaketFehler(
            f"{', '.join(sorted(gesetzt_aber_taub))} wird fuer diesen Eingabetyp "
            f"({_TYPBEZEICHNUNG[eingabetyp]}) NICHT ausgewertet. Abbruch statt "
            "Schweigen: sonst laege ein Ergebnis vor, das ohne die vorgelegte "
            "Angabe entstanden ist, und niemand saehe es ihm an."
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prueft ein exportiertes PHM-Siegel-Paket oder einen Archiv-"
        "Zugehoerigkeitsnachweis, ohne Server, Datenbank oder Netz.",
        epilog="Anleitung fuer Pruefer: docs/VERIFIKATION.md",
    )
    parser.add_argument(
        "paket",
        help="Pfad zur BagIt-Ablage (Verzeichnis), zur nackten Paketdatei (JSON), zu einem "
        "Archiv-Nachweis-Paket, zu einem Verzeichnis-Abzug (Ordner mit verzeichnis.jsonl) "
        "oder zu einem Konsistenz-Paket; der Typ wird erkannt, siehe docs/VERIFIKATION.md",
    )
    parser.add_argument(
        "--tsa-cert",
        action="append",
        help="Zertifikat einer Zeitstempelstelle (PEM oder DER) als Vertrauensanker fuer "
        "Schritt 4b; beim Doppel-Anker mehrfach angeben (je Dienst eines)",
    )
    parser.add_argument(
        "--public-key",
        help="oeffentlicher Ed25519-Schluessel (Hex, 32 Byte) aus der Schluesselhistorie "
        "der Instanz, als Vertrauensanker fuer Schritt 3. EIN Schluessel fuer ALLE "
        "Objekte: ueber einem Abzug mit Schluesselrotation scheitert das zwangslaeufig, "
        "dafuer gibt es --key-history. ZUSAMMEN mit --key-history hat die Historie "
        "Vorrang und dieser Schluessel bleibt UNANGEWANDT (docs/VERZEICHNIS.md)",
    )
    parser.add_argument("--public-key-file", help="Datei mit dem oeffentlichen Schluessel (Hex)")
    parser.add_argument("--key-history",
                        help="veroeffentlichte Schluesselhistorie (JSON, backend/keys/"
                             "*_key_history.json). Loest den Schluessel ueber die key_id auf "
                             "und prueft das Gueltigkeitsfenster - im Gegensatz zu einem "
                             "einzelnen --public-key ueberlebt die Pruefung damit eine "
                             "Schluesselrotation - und hat vor ihm Vorrang, wenn beide "
                             "angegeben sind. Beim Siegel-Paket ist sie ausserdem die "
                             "einzige Quelle ausserhalb des Pakets: erst mit ihr ist das "
                             "vierte Merkmal der Feststellungsliste erfuellbar (Schritt 3c)")
    parser.add_argument(
        "--archiv-public-key",
        help="oeffentlicher Ed25519-Schluessel der ARCHIV-Wochenmanifeste (Hex). Ein anderer "
        "als --public-key. Vertrauensanker fuer Schritt 1d, wenn eine Ablage einen "
        "archiv_nachweis.json mitliefert; ohne ihn prueft 1d gegen den Schluessel im "
        "Nachweis und sagt das im Befund",
    )
    parser.add_argument(
        "--dokument",
        help="nur beim Archiv-Nachweis: die Datei, deren Zugehoerigkeit belegt werden soll; "
        "ihr SHA-256 wird gegen die Prueffsumme in der Index-Zeile gehalten",
    )
    parser.add_argument(
        "--pin",
        help="nur beim Verzeichnis: frueher angehefteter Stand (JSON), gegen den der vorgelegte "
        "Abzug gehalten wird - erst dieser Vergleich macht die Beobachtung aus (Schritt V5)",
    )
    parser.add_argument(
        "--anheften",
        metavar="DATEI",
        help="nur beim Verzeichnis: den juengsten Stand des vorgelegten Abzugs in DATEI "
        "aufbewahren (nur, wenn die Pruefung bestanden hat). Write-once (0444, atomar "
        "ersetzt), Protokoll beobachtungen.jsonl daneben, je Zeile mit dem Namen von DATEI; "
        "liegt DATEI schon vor, nur zusammen mit --pin DATEI. Fehlt DATEI, waehrend das "
        "Protokoll fruehere Anheftungen von DATEI ausweist, ist das ein Bruch",
    )
    parser.add_argument("--json", action="store_true", help="Ergebnis als JSON statt Klartext ausgeben")
    args = parser.parse_args(argv)

    archiv_nachweis = False
    verzeichnis = False
    konsistenz = False
    try:
        public_key = _load_public_key(args)
        # Der Vorrang gehoert AN DEN AUFRUF, nicht nur ins Ergebnis (#161):
        # wer beide Optionen setzt, soll es hier lesen und nicht spaeter einen
        # Befund am Gegenstand suchen, der in Wahrheit an seiner Kommandozeile
        # steht. Beim Verzeichnis-Abzug und beim Archiv-Nachweis spannt ein
        # Lauf ueber MEHRERE signierte Objekte, die nach einer Rotation
        # verschiedene Schluessel tragen - dort kann ein einzelner vorgelegter
        # Schluessel nicht zu allen passen.
        if public_key and args.key_history:
            print(
                "HINWEIS: --key-history und --public-key zusammen angegeben. Die Historie "
                "hat Vorrang; --public-key wird NICHT zusaetzlich angewandt (er kann ueber "
                "einer Rotation nicht zu allen Objekten passen, siehe docs/VERZEICHNIS.md). "
                "Der Bericht weist das aus.",
                file=sys.stderr,
            )
        trusted = [load_certificate_file(p) for p in args.tsa_cert] if args.tsa_cert else None
        if _ist_verzeichnis(args.paket):
            verzeichnis = True
            package, bag_check = load_verzeichnis(args.paket), None
        elif not os.path.isdir(args.paket) and \
                _json_typ(args.paket, "paket_typ") == KONSISTENZ_PAKET_TYPE:
            konsistenz = True
            with open(args.paket, "r", encoding="utf-8") as fh:
                package, bag_check = json.load(fh), None
        elif os.path.isdir(args.paket):
            package, bag_check = load_bag(args.paket)
        elif _ist_archiv_nachweis(args.paket):
            # Zweiter Eingabetyp, erkannt am package_type (Teil 7b): ein
            # Archiv-Zugehoerigkeitsnachweis statt eines Siegel-Pakets.
            archiv_nachweis = True
            package, bag_check = load_archive_proof(args.paket), None
        else:
            package, bag_check = load_package(args.paket), None
        eingabetyp = ("verzeichnis" if verzeichnis else
                      "konsistenz" if konsistenz else
                      "archiv_nachweis" if archiv_nachweis else "siegel_paket")
        _pruefe_optionen(eingabetyp, args)
        if verzeichnis and args.anheften:
            # E20: dieselbe Wache wie beim Beobachter, aus derselben Funktion.
            # Vor der Pruefung: ohne Gedaechtnis traegt dieser Lauf keine
            # Aussage ueber die Zeit, und angeheftet wuerde er auch nicht.
            luecke = gedaechtnisluecke(args.anheften)
            if luecke is not None:
                if args.json:
                    print(json.dumps(luecke, ensure_ascii=False, indent=2))
                else:
                    print("=== BRUCH: GEDAECHTNISLUECKE ===")
                    print(luecke["grund"])
                    print(f"Abhilfe: {luecke['abhilfe']}")
                    print("Es wurde nichts geprueft und nichts angeheftet.")
                return 1
            # Ein vorhandener Pin wird nur fortgeschrieben, wenn dieser Lauf
            # gegen GENAU ihn geprueft hat (V5). Sonst ersetzte ein Lauf ohne
            # Vergleich das Gedaechtnis durch einen ungeprueften Stand - der
            # stille Neuanfang, nur auf anderem Weg.
            if os.path.lexists(args.anheften) and not (
                    args.pin and os.path.exists(args.pin)
                    and os.path.samefile(args.pin, args.anheften)):
                raise PaketFehler(
                    f"--anheften {args.anheften}: dort liegt schon ein angehefteter Stand. "
                    "Fortgeschrieben wird er nur nach dem Vergleich mit genau ihm: "
                    f"--pin {args.anheften} --anheften {args.anheften}.")
        if verzeichnis:
            result = verify_verzeichnis(
                package,
                pin=load_pin(args.pin) if args.pin else None,
                public_key_hex=public_key,
                trusted_cert_der=trusted,
                # args.key_history direkt, kein getattr mit Default (#160): die
                # Option ist am selben Parser immer deklariert. Ein getattr
                # haette ein Umbenennen in ein stilles None verwandelt - die
                # Pruefung liefe dann ohne Historie weiter und meldete
                # "bestanden".
                key_history=(lade_key_history(args.key_history)
                             if args.key_history else None),
            )
        elif konsistenz:
            # Die Koepfe im Paket werden mit demselben Schluesselwissen
            # geprueft wie im vollen Durchlauf; ein still geschluckter
            # --key-history waere hier derselbe Fehler wie in #102 (d).
            result = verify_konsistenz_paket(
                package,
                public_key_hex=public_key,
                key_history=(lade_key_history(args.key_history)
                             if args.key_history else None),
            )
        elif archiv_nachweis:
            result = verify_archive_proof(
                package,
                public_key_hex=public_key,
                trusted_cert_der=trusted,
                dokument_pfad=args.dokument,
                key_history=(lade_key_history(args.key_history)
                             if args.key_history else None),
            )
        else:
            result = verify_package(
                package,
                public_key_hex=public_key,
                trusted_cert_der=trusted,
                bag_check=bag_check,
                archiv_public_key_hex=args.archiv_public_key,
                key_history=(lade_key_history(args.key_history)
                             if args.key_history else None),
            )
    except PaketFehler as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2

    if verzeichnis and args.anheften:
        if result["passed"]:
            neuer = result["neuer_pin"]
            try:
                hefte_an(args.anheften, neuer, {
                    "angeheftet_von": "phm_verifier.py",
                    "quelle": neuer["quelle"],
                    "stand": neuer["kopf_nr"],
                    "verifier_exit": 0,
                    "zeilen": result["zeilen"],
                })
            except OSError as e:
                print(f"FEHLER: Pruefung bestanden, aber NICHT angeheftet ({args.anheften}): {e}",
                      file=sys.stderr)
                return 2
        else:
            print(
                f"NICHT angeheftet: die Pruefung ist nicht bestanden ({args.anheften} "
                "unveraendert). Ein gescheiterter Abzug darf nie zum neuen Bezugspunkt werden.",
                file=sys.stderr,
            )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if verzeichnis:
            kopf = package["koepfe"][-1]
            print("PHM-Verifier: Verzeichnis der Archiv-Wurzeln")
            print(f"Abzug:     {package['datei']}")
            print(f"Stand:     Kopf {kopf.get('kopf_nr')}, {result['zeilen']} Zeilen, "
                  f"created_at {kopf.get('created_at')}, key_id {kopf.get('key_id')}")
            print(f"Wurzel:    {kopf.get('root_hash')}")
            print(f"Versionen: Kopf v{result['kopf_version']} "
                  "(gegen diese Serialisierung wurde geprueft)")
        elif konsistenz:
            alt_k, neu_k = package.get("alt") or {}, package.get("neu") or {}
            print("PHM-Verifier: Konsistenznachweis zweier Verzeichnis-Staende")
            print(f"Paket:     {args.paket}")
            print(f"Frueher:   Kopf {alt_k.get('kopf_nr')}, {alt_k.get('tree_size')} Zeilen, "
                  f"created_at {alt_k.get('created_at')}, key_id {alt_k.get('key_id')}")
            print(f"Spaeter:   Kopf {neu_k.get('kopf_nr')}, {neu_k.get('tree_size')} Zeilen, "
                  f"created_at {neu_k.get('created_at')}, key_id {neu_k.get('key_id')}")
            print(f"Versionen: Paket v{package.get('paket_version')}, Kopf "
                  f"v{neu_k.get('kopf_version')} (gegen diese Serialisierungen wurde geprueft)")
        elif archiv_nachweis:
            n, m = package["nachweis"], package["manifest"]
            print("PHM-Verifier: Archiv-Zugehoerigkeitsnachweis")
            print(f"Nachweis:  {args.paket}")
            print(f"Eintrag:   {n.get('entry_id')}, Position {int(n.get('leaf_index', 0)) + 1} "
                  f"von {n.get('tree_size')}")
            print(f"Wurzel:    {n.get('root_hash')} (Manifest {m.get('manifest_nr')}, "
                  f"Woche {m.get('woche')})")
            print(
                f"Versionen: Nachweis v{result['package_version']}, Manifest "
                f"v{result['manifest_version']} (gegen diese Serialisierungen wurde geprueft)"
            )
        else:
            seal = package["seal"]
            print("PHM-Siegel-Verifier")
            print(f"Paket:     {args.paket}")
            print(f"Siegel:    sealed_at {seal.get('sealed_at')}, key_id {seal.get('key_id')}")
            print(
                f"Versionen: Umschlag v{result['envelope_version']}, Siegel v{result['seal_version']} "
                "(gegen diese Serialisierungen wurde geprueft)"
            )
        print()
        for check in result["checks"]:
            marker = {BESTANDEN: "[OK]  ", NICHT_BESTANDEN: "[FEHL]", UEBERSPRUNGEN: "[--]  "}[check["ergebnis"]]
            print(f"{marker} {check['pruefung']}: {check['ergebnis']}")
            print(f"        {check['begruendung']}")
        print()
        if result.get("stufe"):
            print(f"Feststellung: {result['stufe']} - {result['stufe_begruendung']}")
        for f in result.get("feststellungen") or []:
            print(f"  [{f['ergebnis']:4}] {f['merkmal']} (Schritt {f['schritt']})")
        print(f"Gesamturteil: {result['verdict']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
