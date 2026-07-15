# Deed corpus transparency log

This public repository is a hash-only, append-only chronology for the private
Spaceport deed-plotting real-corpus registry. It contains no deeds, surveys,
names, addresses, parcel identifiers, geometry, or private truth. Each event
anchors only a one-way SHA-256 root, event count, request nonce, and timestamp.

The `main` branch rejects force pushes and deletion. Updates are serialized by
the custodian workflow, and each resulting `anchors.json` is attested by GitHub
Actions OIDC. The private verifier requires a continuous root chain and the
latest attested public anchor before corpus intake, consumption, or final DoD.

The public event chronology covers quarantine, assignment, truth sealing,
one-time source release, consumption, execution sealing, judge challenges, and
judge result sealing. Only hash commitments and event metadata are public.
