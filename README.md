# phm-verifier

*Deutsch; [English below](#english).*

## Wozu dieses Repository da ist

Der Portfolio Health Monitor (PHM) der Esox Consult GmbH versiegelt seine
Aufzeichnungen (Ed25519) und laesst sie extern zeitstempeln (RFC 3161). Wer
eine solche Aufzeichnung pruefen will, braucht drei Dinge, die er **nicht**
aus dem vorgelegten Paket beziehen sollte: das Pruefwerkzeug, die
oeffentlichen Schluessel des Herausgebers und das Zertifikat der
Zeitstempelstelle. Genau das liegt hier, und sonst nichts.

Das Repository wird aus dem nicht oeffentlichen Hauptrepository **erzeugt**,
mit dem Werkzeug `scripts/pruef_repo_export.py` (nicht oeffentlich), und nie von Hand gepflegt. Eine Aenderung,
die hier direkt gemacht wird, ist beim naechsten Stand wieder weg. Jeder Stand
traegt ein Git-Tag; der erste Stand ist `v1.0.0`. Ein Werk-Paket nennt in
seiner Anleitung den Tag, zu dem seine Kopie des Pruefwerkzeugs gehoert.

| Pfad | Inhalt |
|---|---|
| `phm_verifier.py` | Pruefwerkzeug: eine Datei, nur Python-Standardbibliothek (3.8 oder neuer), kein Netz, keine Installation |
| `phm_beobachter.py` | Beobachter fuer das oeffentliche Verzeichnis der Archiv-Wurzeln (holt ab, laesst `phm_verifier.py` pruefen, meldet Brueche) |
| `keys/*_key_history.json` | Schluesselhistorien, nur oeffentliche Ed25519-Schluessel |
| `keys/tsa_vertrauen/` | gepinntes Signer-Zertifikat der Zeitstempelstelle |
| `anker/` | RFC-3161-Anfragen (`.tsq`) und Antworten (`.tsr`) ueber den SHA-256 jeder Schluesselhistorie |
| `docs/` | Pruefanleitung (Auszuege, Pfade auf dieses Repository umgeschrieben) |
| `MANIFEST.sha256` | SHA-256 jeder Datei dieses Standes |

## Wie pruefen

```
shasum -a 256 -c MANIFEST.sha256
python3 -I phm_verifier.py PAKET \
    --key-history keys/seal_key_history.json \
    --tsa-cert keys/tsa_vertrauen/freetsa_tsa.crt
```

`PAKET` ist eine BagIt-Ablage, eine Paketdatei, ein Archiv-Nachweis oder ein
Verzeichnis-Abzug; der Typ wird erkannt. Welche Historie: Belegakten
(`key_id` beginnt mit `ba-`) `keys/seal_key_history.json`, Archiv-Manifeste
und Verzeichnis (`am-`) `keys/archiv_manifest_key_history.json`, eigene
Texte wie das Kriterienwerk (`wk-`) `keys/werk_key_history.json`.
Exit-Code `0` = alle durchgefuehrten Pruefungen bestanden, `1` = mindestens
eine nicht bestanden, `2` = Eingabe unbrauchbar. Ein uebersprungener Schritt
steht als uebersprungen im Urteil, nie als bestanden. Vollstaendig:
[`docs/VERIFIKATION.md`](docs/VERIFIKATION.md), fuer das Verzeichnis
[`docs/VERZEICHNIS.md`](docs/VERZEICHNIS.md).

Liegt einem Paket eine eigene Kopie des Pruefwerkzeugs bei (etwa
`data/phm_verifier.py` in einem Werk-Paket), halten Sie sie gegen diese hier:
`cmp data/phm_verifier.py phm_verifier.py`.

### Schluesselhistorien dieses Standes

| Datei | SHA-256 | key_id | art | gueltig ab | gueltig bis |
|---|---|---|---|---|---|
| `keys/archiv_manifest_key_history.json` | `c6f2d5b0722b42a12a7eb0b76400aed0a50828be1c8c51a6e752252380dbb017` | `am-4d7f1c3d46c7c12b` | demo | 2026-07-30T22:43:16Z | 2026-08-03T10:20:37Z |
|  |  | `am-c7e8bb1f83a8c0e9` | ephemer | 2026-07-31T13:32:15Z | 2026-07-31T13:32:15Z |
|  |  | `am-7aa95b5eea386de8` | produktiv | 2026-08-03T10:20:37Z | laeuft |
| `keys/seal_key_history.json` | `e3cc086a0cf6628dbcbc6dd086f42debc9cba25fbfca7f8a6a90d9b30d6dcb12` | `ba-e21c94432277974d` | demo | 2026-07-30T12:45:05Z | 2026-08-03T10:20:37Z |
|  |  | `ba-621f430af3eb39e1` | produktiv | 2026-08-03T10:20:37Z | laeuft |
| `keys/werk_key_history.json` | `a2d191620bda6b02c37988f3b48333e949f7291d4381b05c5bcd76b9b2ade7d6` | `wk-cf838e4c808c6aa0` | demo | 2026-07-31T20:03:54Z | 2026-11-10T00:00:00Z |
|  |  | `wk-e63d88bb484d4863` | produktiv | 2026-11-10T00:00:00Z | laeuft |

Das Feld `art` sagt, was ein Schluessel beweist: `produktiv` (geheimer Teil
unter Verwahrung, nicht im Repository), `ephemer` (einmal verwendet, geheimer
Teil nie gespeichert), `demo` (eine Signatur damit beweist keine Urheberschaft
durch einen getrennt verwahrten Schluessel: der geheime Teil ist offengelegt
oder seine Verwahrung ist noch nicht gesichert). Beim Werk-Schluessel
`wk-cf838e4c808c6aa0` gilt das zweite: `demo`, weil die getrennte Verwahrung
offen ist (Frist 31.12.2026), nicht weil der geheime Teil veroeffentlicht waere.

### Gepinntes Zertifikat der Zeitstempelstelle

| Datei | SHA-256 der Datei | SHA-256 der DER-Bytes |
|---|---|---|
| `keys/tsa_vertrauen/freetsa_tsa.crt` | `8bfb0305bb64e2571ca507552ef3245cb1c2fee8728e0ff8689225081ea13467` | `32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc` |

Gepinnt ist das **Signer**-Zertifikat, verglichen wird Byte fuer Byte. Die
Wurzel darueber (`cacert.pem` bei freetsa.org) beziehen Sie fuer `openssl`
selbst beim Anbieter, aus einer Quelle, der Sie vertrauen.

## Verankerung der Schluesselhistorien

Die Schluesselhistorie ist eine gewoehnliche JSON-Datei, sie ist nicht
signiert. Damit ein stilles Umschreiben sichtbar wird, liegt sie in einem
oeffentlichen Git mit getaggten Staenden, und ihr SHA-256 wird bei einer
Zeitstempelstelle nach RFC 3161 gestempelt. Die Dateinamen unter `anker/`
lauten `<historie>.<erste 16 Hex-Zeichen des SHA-256>.tsq` (Anfrage) und
`<historie>.<16 Hex>.<stelle>.tsr` (Antwort). Antworten frueherer Staende
bleiben liegen; sie gehoeren zu dem Stand, dessen Hash ihr Name traegt.

Mit OpenSSL, ohne unser Werkzeug (`HISTORIE` und `ANKER` setzen, zum Beispiel
`HISTORIE=keys/seal_key_history.json`):

```
H=$(shasum -a 256 "$HISTORIE" | cut -d' ' -f1)
openssl ts -verify -digest "$H" -in "$ANKER" -CAfile cacert.pem -untrusted keys/tsa_vertrauen/freetsa_tsa.crt
```

Mit `phm_verifier.py` (volle CMS-Pruefung der Token-Signatur, das
Signer-Zertifikat Byte fuer Byte gegen das gepinnte gehalten, der bezeugte
Hash gegen den nachgerechneten):

```
python3 -I - "$ANKER" "$HISTORIE" keys/tsa_vertrauen/freetsa_tsa.crt <<'EOF'
import hashlib, importlib.util, sys
spec = importlib.util.spec_from_file_location("phm_verifier", "phm_verifier.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
_, antwort, _ = V._read_tlv(open(sys.argv[1], "rb").read(), 0)
teile = V._children(antwort)
status = V._decode_integer(V._children(teile[0][1])[0][1], "PKIStatus")
token = V._der(0x30, teile[1][1])
info = V.verify_timestamp_token(token, V.load_certificate_file(sys.argv[3]))
soll = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
gut = (status in (0, 1) and info["hash_algo_oid"] == V.OID_SHA256
       and info["hashed_message"] == soll and info["trusted_cert_match"] is True)
print(("BESTANDEN" if gut else "NICHT BESTANDEN"), info["gen_time"], info["hashed_message"])
sys.exit(0 if gut else 1)
EOF
```

Bestanden heisst: genau dieser Dateistand der Historie existierte spaetestens
zu der Zeit, die das Token nennt, bezeugt von der Stelle, deren Zertifikat
gepinnt ist.

## Was dieses Repository NICHT beweist

- **Nicht die inhaltliche Richtigkeit** einer gesiegelten Zahl oder Aussage.
  Ein Siegel belegt, WAS aufgezeichnet wurde und WANN, nicht, dass es stimmt.
- **Nicht, dass niemandem ein anderer Stand gezeigt wurde.** Der Anker belegt
  nur, dass ein Stand zu einer Zeit existierte. Gegen einen zweiten, parallel
  gezeigten Stand hilft nur, dass Sie Ihren Stand aufbewahren (Tag, Hash,
  `--anheften`) und spaetere dagegen halten.
- **Nicht die Urheberschaft eines Demo-Schluessels** (`art: demo`): eine
  solche Signatur beweist keine Urheberschaft durch einen getrennt verwahrten
  Schluessel. Das gilt auch fuer den Werk-Schluessel `wk-cf838e4c808c6aa0`,
  dessen getrennte Verwahrung offen ist (Frist 31.12.2026); seine Siegel
  belegen Unveraendertheit und Zeitpunkt der Kriterienwerk-Fassungen, nicht
  mehr.
- **Nicht die Kette zur Wurzel und nicht den Sperrstatus** des
  TSA-Zertifikats: `phm_verifier.py` vergleicht das Signer-Zertifikat Byte fuer
  Byte und baut keine Kette. Die Kette prueft `openssl ts -verify`, den
  Sperrstatus keiner der beiden Wege.
- **Nicht, dass wir dieses Werkzeug selbst einsetzen.** Es ist das Werkzeug,
  das SIE ausfuehren; deshalb liegt es hier lesbar und ohne Abhaengigkeiten.
- **Nicht gegen den Hoster.** Tags lassen sich verschieben oder loeschen.
  Ein gestempelter Hash, den Sie aufbewahrt haben, laesst sich nicht
  zuruecknehmen.

Sicherheitsluecken melden: [SECURITY.md](SECURITY.md). Lizenz: Apache-2.0
([LICENSE](LICENSE)).

Copyright 2026 Esox Consult GmbH

## English

This repository contains only what a third party needs to verify records of
the Portfolio Health Monitor (PHM) by Esox Consult GmbH without trusting us:
the verifier (`phm_verifier.py`, one file, Python 3.8+ standard library only,
no network), the observer for the public directory of archive roots
(`phm_beobachter.py`), the key histories (public Ed25519 keys only, under
`keys/`), the pinned signer certificate of the time-stamping authority
(`keys/tsa_vertrauen/`), RFC 3161 time-stamps over the SHA-256 of each key
history (`anker/`) and the verification guide (`docs/`, in German). It is
**generated** from our private main repository and never edited by hand;
every state is tagged, the first one `v1.0.0`.

**Verify:**

```
shasum -a 256 -c MANIFEST.sha256
python3 -I phm_verifier.py PACKAGE \
    --key-history keys/seal_key_history.json \
    --tsa-cert keys/tsa_vertrauen/freetsa_tsa.crt
```

Exit code `0` = all performed checks passed, `1` = at least one failed,
`2` = unusable input. A skipped step is reported as skipped, never as passed.
Choose the history by the `key_id` prefix: `ba-` seal history, `am-` archive
manifest history, `wk-` works history. The anchors under `anker/` are verified
with `openssl ts -verify` or with `phm_verifier.py` as shown in the German
section above (the commands are the same).

**What this does NOT prove:** that recorded content is correct; that nobody
was shown a different state (keep your own copy, tag or hash and compare
later ones against it); authorship by a separately held key for keys marked `art: demo` (secret part
disclosed, or its separate custody not yet in place; for the works key
`wk-cf838e4c808c6aa0` it is the latter, deadline 31.12.2026); the
certificate chain or revocation status of the TSA certificate (the verifier
compares the signer certificate byte for byte, `openssl` checks the chain,
neither checks revocation); that we run this tool ourselves; protection
against the hosting provider (tags can be moved; a stamped hash you kept
cannot be taken back).

Report vulnerabilities: [SECURITY.md](SECURITY.md). License: Apache-2.0
([LICENSE](LICENSE)).

Copyright 2026 Esox Consult GmbH
