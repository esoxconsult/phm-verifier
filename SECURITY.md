# Sicherheit / Security

## Meldeweg

Schwachstellen im Pruefwerkzeug (`phm_verifier.py`, `phm_beobachter.py`), in
den Schluesselhistorien, in den Ankern oder in der Pruefanleitung melden Sie
bitte vertraulich per E-Mail an **security@esoxconsult.com**, nicht als
oeffentliches Issue.

Hilfreich sind: betroffene Datei und Stand (Tag oder Zeile aus
`MANIFEST.sha256`), eine Beschreibung der Auswirkung, und wenn moeglich ein
Paket oder eine Befehlsfolge, mit der sich der Fund nachstellen laesst. Am
schwersten wiegt ein Paket, das `phm_verifier.py` als bestanden ausweist,
obwohl es veraendert oder nicht von uns gesiegelt wurde.

Dieses Repository wird erzeugt; eine Korrektur kommt als neuer, getaggter
Stand, nicht als Aenderung an einem bestehenden.

## Reporting

Please report vulnerabilities in the verifier (`phm_verifier.py`,
`phm_beobachter.py`), the key histories, the anchors or the verification
guide confidentially by e-mail to **security@esoxconsult.com**, not as a
public issue.

Useful: affected file and state (tag or line from `MANIFEST.sha256`), the
impact, and if possible a package or command sequence that reproduces it. The
most serious class is a package that `phm_verifier.py` reports as passed
although it was altered or not sealed by us.

This repository is generated; a fix arrives as a new tagged state, never as
a change to an existing one.
