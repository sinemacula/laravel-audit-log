# Integrity

## Purpose

This note records the audit log's integrity, from one row to the whole log: how every entry is signed when it is
finalised, the one canonical encoding the signature is computed over, the key ring that signs and verifies, and what
verifying a stored row answers; then how entries are sealed into a signed chain of membership manifests, how each seal
is anchored outside the application's writable trust boundary, how pruning keeps the log verifiable, and what
`audit-log:verify` establishes and reports. A row's signature shows that the row is as it was written; a seal shows
which rows it holds and that none of them has since changed or gone; an anchor shows that the seals themselves were not
rewritten or cut short. The encodings, the columns and fields they cover and the keys that verify them are fixed here
and versioned, by `integrity_version` for a row and by `v` and `algorithm_version` for a seal; a change to any of them
is a new version, never an edit of the old one. What none of this promises is in `threat-model.md`.

## Invariants

- Every entry is finalised once, by `Records\RecordFinaliser`, which stamps `recorded_at` from the clock (never before
  `occurred_at`) and signs it; retries and replays reuse the finalised record, never sign again.
- The signature is HMAC-SHA256, as 64 lower-case hex characters in `hmac`, under the ring's signing key, whose id is
  stored in `key_id`. It covers the 35 signed columns, every column but `hmac`: the 32 captured ones, then
  `recorded_at`, `integrity_version` and `key_id`. `integrity_version` is 1, and it is signed too.
- The canonical encoding of version 1 (`Integrity\CanonicalEncoder`) works on decoded stored values and never
  normalises, sanitises, truncates or repairs them. `null`, `true` and `false` are themselves; an integer is its decimal
  digits; a string is JSON with fixed flags (UTF-8 and `/` unescaped, `"` and `\` escaped, controls as `\u00XX`,
  U+2028 and U+2029 escaped); a list keeps its order; a map, a PHP array that is not a list or a decoded JSON object,
  has its keys sorted bytewise and is always written as a map, so `{}` and numeric keys survive. A float, any other
  object and invalid UTF-8 are refused with an `\UnexpectedValueException`: the package stores decimals as strings.
- Every signed column is required to verify, nullable ones included; a missing column is malformed, never `null`.
  Columns a row has beyond the version's list are not signed, and `audit-log:check` reports them.
- The captured-content digest is SHA-256 over the canonical encoding of the 32 captured columns, leaving out the four
  finalisation columns. The store compares it to tell a stored duplicate from a conflict, so a record finalised twice,
  at another time or under another key, is still the same record.
- With `integrity.keys` empty, the key is derived from `app.key`: a `base64:` key is decoded to bytes first, then
  HKDF-SHA256 with the info `sinemacula/audit-log:integrity:v1` gives the 32-byte secret. Its id is a fingerprint,
  `d` followed by the first 16 hex characters of the HMAC-SHA256 of `audit-log:key-id` under the secret, so a rotated
  `app.key` gets a new id. Keys derived from `app.previous_keys` in the same way verify only, never sign.
- With `integrity.keys` set, the ring is exactly those keys, and `integrity.current` names the one that signs. Each id
  is 1 to 32 letters, digits, dots, underscores or hyphens starting with a letter or a digit, so it fits `key_id`;
  each secret, once decoded (`base64:` strictly), is at least 32 bytes and is the HMAC key itself. A malformed ring
  fails closed on every call and never falls back to `app.key`.
- The ring is rebuilt from the settings on every call, so a worker always signs with the configured key. A key's
  secret is never in a message, a stack trace, a dump, a JSON encoding or an export.
- Verification (`RecordSigner::verifies()`) answers `false` only when the signature does not match. A key id that is
  not in the ring is an `Integrity\UnknownKeyException` naming the id; an unsupported `integrity_version`, a missing
  column, a malformed `hmac` or a value with no canonical form is an `\UnexpectedValueException`. Verification keeps the
  evidence as it is and never repairs it.
- A record kept outside the entries table, in the outbox or a spill line, is verified on the way back in, by
  `Records\EnvelopeCodec`. Only one that verifies reaches the store, and it arrives with its own `recorded_at`, key id
  and HMAC. A replay verifies and never re-signs, because a new signature would vouch for bytes nobody can now check, so
  a removed signing key means restoring the key or leaving the record quarantined. A line marked `unsigned` has no
  signature to verify, and is counted and left.
- Removing a key from the ring leaves its rows unverifiable. Verification keys are kept as long as the rows they
  signed, independently of when an encryption key is retired: moving `app.key` into `app.previous_keys` keeps the old
  derived key verifying, and dropping it from there does not. Choose the managed ring before going live, because rows
  signed under a derived key cannot yet be carried into it.
- A row's signature proves that row alone: it shows neither that every entry is present nor that none was deleted. That
  is what a seal adds, for the rows it holds.
- A seal is an explicit membership manifest: one row of `integrity.checkpoints_table` and one row of
  `integrity.members_table` per entry it holds, each entry in at most one seal. An entry is unsealed exactly when no
  member row names it. Entries are read in `(recorded_at, id)` order, on the entries table's `<table>_recorded_index`,
  only so batches are deterministic. Membership, not ordering, is what is sealed: no id or time is a high-water mark, so
  a row that commits late, whatever its UUID or time, joins a later seal.
- Sealing is separate from recording: no application-level lock or inline chain is added to recording, so an entry is
  inserted as it always was and sealed later, in a transaction of its own. That is not a promise that a write never
  waits, since SQLite has one writer and a sealer's transaction holds it like any other writer's.
- `integrity.seal.settle_seconds` (default 0) keeps a seal from holding an entry recorded less than that long before the
  run began. The settle delay is an operational delay, not a correctness mechanism: a transaction's visibility already
  keeps an uncommitted row out of every seal, and the bound is fixed once, when the run starts.
- Each seal is one attempt in one outermost transaction on the storage connection's writer, and sealing refuses to run
  inside a transaction already open there. The attempt reads the head afresh, selects with a plain `SELECT`, never a
  locking read, and inserts the checkpoint and then every member with parameterised `INSERT … VALUES`, never
  `INSERT … SELECT` and never an insert that ignores a conflict, so a concurrent sealer's seal of the same sequence or
  the same entry fails the attempt as a whole.
- An attempt lost to a concurrent writer (a duplicate seal or member, a deadlock, a serialisation failure, a lock wait
  timeout, PostgreSQL's `lock_timeout` by its SQLSTATE `55P03`, or a locked SQLite database, which covers its busy
  snapshot) is rolled back whole and made again from scratch,
  the head and the selection included, after a jittered wait, at most `integrity.seal.max_attempts` times. A savepoint
  retry is never used. A lost connection is never retried, because its commit may have happened.
- A seal's digest is the SHA-256 of the canonical encoding of every immutable field of the seal, and its signature is an
  HMAC-SHA256 under a seal key derived from the ring key the seal names; there is no public-key signer. The chain is
  over seal digests: each seal holds the id and the digest of the one before it, and genesis is sequence 1 with no
  previous fields.
- Verification selects the historical key by the stored id, never the current key, for an entry, a seal and a prune
  record alike, so rotation needs no rewrite and a segment may hold entries signed under several keys.
- The docs give separate lifetimes for encryption keys, row-HMAC keys and seal-verification keys. An encryption key
  (`app.key` for the outbox, an owner's key for an encrypted field) may be retired, or destroyed to erase, on its own
  schedule; a row-HMAC key is kept as long as the rows it signed; and a seal-verification key, the ring key a seal
  names, is kept as long as the seal, which outlives its pruned entries. A key id is chosen once: a key id is never
  reused for different material, since every row and seal signed under it would then fail or, worse, verify under the
  wrong key.
- An anchor (`Contracts\CheckpointAnchor`) keeps each seal's `Integrity\SealSummary`, the tuple of `log_id`, `sequence`,
  seal id and seal digest, outside the application's writable trust boundary. Anchoring the same seal again returns the
  same receipt and changes nothing; another digest for a sequence the anchor holds is an
  `Integrity\Anchors\AnchorConflictException`, never a replacement.
- Anchoring runs after the seal commits and never blocks sealing, not even when an anchor setting is malformed; a seal
  that is not yet anchored is anchored by a later run. The receipt columns are a cache, never the authority: the
  anchorer picks the seals to anchor from the anchor's own head, and verification asks for the anchor's head
  independently of every receipt and settles anchoring by it, asking the anchor to confirm a receipt only when the head
  cannot settle it, so editing the receipt columns can at most unanchor a seal, and with discovery changes nothing.
- An anchor's head beyond the local tail, another digest at its sequence, or a head with no local log is `tampered` and
  `contradicted`. An empty remote with a non-empty local log is `unanchored`, and an empty remote with an empty log
  agree.
- Pruning deletes entries only, of whole sealed segments, and keeps every checkpoint and member row. Missing entries are
  `pruned` only under a signed prune record that binds exactly that seal. Pruning never excuses a bad signature, a
  broken chain or an anchor contradiction.
- Every verification reports the exact range it checked and the head it observed, and each segment has two separate
  fields, integrity and anchoring, so `pruned` cannot hide an anchoring failure. A ranged run never establishes the
  integrity of the whole log.
- Verification never repairs and never re-signs. Nothing ever updates an entry or a member row, and the only columns
  written after a seal row is inserted are its four anchor columns: `anchor`, `anchor_receipt`, `anchored_at` and
  `anchor_error_class`.
- A caught failure is named by its class alone: `audit-log:seal` and `audit-log:verify` print, dispatch and report no
  message, statement, binding or value of an entry, and the exceptions the package raises for integrity have no previous
  exception.

## Success Path

- With no integrity settings, every entry is signed under the key derived from `app.key` and verifies with it.
- After `app.key` is rotated and the old key moved to `app.previous_keys`, new entries are signed under the new derived
  key and old ones still verify.
- With a managed ring, entries are signed under `integrity.current`; moving `current` to a new key signs new entries
  with it while every key left in the ring still verifies its rows.
- Every five minutes the scheduled `audit-log:seal` seals the entries recorded since the last seal, a batch per seal,
  each chained onto the one before, then anchors the seals the anchor does not hold yet.
- Daily, `audit-log:seal --sweep` seals any entry the recent passes missed, and `audit-log:verify --strict --sweep-first`
  sweeps again, then verifies every seal, its members, its entries and its anchoring, reports the range and the head,
  and records its completion.
- `php artisan audit-log:check` reports a malformed ring, a short secret, a current key that is not in the ring, a
  malformed integrity setting, a missing integrity table and an anchor disk that is not configured before a deploy.

## Failure / Edge Cases

- A malformed `integrity.keys` or `integrity.current`, an empty or short `app.key` with no managed ring, or malformed
  `app.previous_keys` fails closed with an `\InvalidArgumentException` naming the setting, never its value; nothing is
  signed or verified until it is fixed.
- A stored JSON number that is not a PHP integer (a fraction, an exponent or an integer beyond PHP's range) decodes as
  a float and is refused as malformed; it is never decoded as a string, so a string edited into a bare number never
  verifies as the original.
- A tampered column, a nested property or a microsecond fails verification with `false`.
- A row signed under a key the ring no longer holds raises `UnknownKeyException`; the store lets it propagate rather
  than call the row a conflict.
- An envelope in the outbox or a spill line that fails is refused with a distinct `Records\Enums\EnvelopeFailure`:
  `signature_mismatch`, `unknown_key`, `unsupported_version` or `malformed`. The outbox row is failed and kept, and the
  spill line is counted and left in its file; `delivery.md` has every outcome.
- A malformed integrity setting (a log id outside the grammar, a number outside its range, a schedule that is no cron
  expression, an anchor path that could leave its namespace) fails closed with an `\InvalidArgumentException` naming the
  key, never its value; a malformed schedule is reported and schedules nothing for that run, and the other runs are
  still registered.
- A head whose stored digest disagrees with its fields is never extended (`Integrity\SealChainException::forHead()`,
  finding `seal_digest`), and neither is a head of another log id (`forLog()`, finding `log_mismatch`), so a changed
  `integrity.log_id` or `source.id` stops sealing rather than mixing two logs in one chain. A head signed under a key
  since retired is extended: the anchorer refuses to anchor a seal whose signature fails, and verification reports it.
- A candidate whose id is not a lower-case UUID, whose HMAC is not 64 lower-case hex, or whose `recorded_at` cannot be
  read is left out of the seal and counted, never sealed and never fatal; `audit-log:seal` alarms with finding
  `entry_malformed` and no id, and the row stays unsealed, so verification reports it pending, then overdue.
- An attempt that loses `integrity.seal.max_attempts` times to concurrent writers ends the run with an
  `Integrity\SealContentionException`; anything else that stops sealing, or anchoring, a malformed anchor setting among
  them, is reported as an `Integrity\SealFailedException` naming its class, and dispatches nothing. Either leaves every
  committed seal as it is, and the next run goes on from the head.
- An anchor that fails is unavailable: its class is kept on the seal and in progress, the pass stops, the command warns
  and succeeds, and a later run tries again. Only a strict verification fails on it.
- A crash at any point of sealing leaves either the whole seal or nothing; one between an anchor's remote write and the
  local receipt is recovered by the next run, which receives the same receipt.

## Seals

The envelope (`Integrity\SealEnvelope`) has 14 fields, every immutable column of a seal row: `v` (1), `log_id`, `id` (a
UUID v7), `sequence`, `previous_id`, `previous_digest`, `member_count`, `members_digest`, `first_recorded_at`,
`last_recorded_at`, `sealed_at`, `signer` (`hmac`), `key_id` and `algorithm_version` (1). The stored `seal_digest` and
`signature` are not part of it, and neither are the four anchor columns.

- `members_digest` is the lower-case hex SHA-256 of the canonical encoding of the list `[[entry_id, hmac], …]`, sorted
  bytewise by `entry_id` whatever order the members came in. A seal holds 1 to 50000 members.
- The seal digest, kept in `seal_digest`, is the lower-case hex SHA-256 of the canonical encoding of the envelope, its
  keys sorted bytewise. `previous_digest` is the digest recomputed from the previous seal's fields, not its stored
  column, so a stored digest edited to hide a change breaks the link after it.
- The seal key is `hash_hkdf('sha256', $secret, 32, 'sinemacula/audit-log:seal:v1', '')`: HKDF-SHA256 with the ring
  secret of the seal's `key_id` as the input key material, an empty salt, the info `sinemacula/audit-log:seal:v1` and a
  length of 32 bytes. The signature, in `signature`, is the lower-case hex HMAC-SHA256 under that key of the label
  `audit-log:seal:v1`, a line feed and the 64 hex characters of the seal digest. A row's HMAC uses the secret itself and
  no label, so a row's HMAC is never a seal's signature.
- `log_id` is `integrity.log_id`, or `source.id` when it is `null` or empty, and must be 1 to 64 letters, digits, dots,
  underscores or hyphens starting with a letter or a digit, since it is a path segment of the disk anchor. It is set
  before the first seal and never changed.
- `tests/Fixtures/Integrity/seal-v1.json` holds the golden vectors: the seal key, a members digest, two chained seals'
  canonical forms, digests and signatures, a prune record and a disk anchor object, all reproduced byte for byte.

`Integrity\Sealer` runs batches until one reads fewer entries than a batch, each batch one attempt loop and at most one
seal; only a batch that writes a seal counts towards `integrity.seal.max_batches`, and every batch reads on strictly
after the last row the one before read, so a run always ends.

- **The recent pass** (`audit-log:seal`) starts `integrity.seal.lookback_seconds` before its high-water mark,
  `seal.recent`, the latest entry time a recent pass sealed, which only a recent pass moves forward, so a sweep's seal
  of old rows at the head never pulls the window back to them. Without that mark it starts the lookback before the
  last chained seal's `last_recorded_at`, or at the beginning of the table when there is no seal; it is read once
  before the first batch. Each batch reads at most
  `integrity.seal.batch` entries that no member row names, an anti-join in `(recorded_at, id)` order, so the pass reads
  the whole lookback window every run, sealed rows included.
- **The sweep** (`audit-log:seal --sweep`) reads the whole table, a window of at most `integrity.seal.batch` entries at
  a time after its cursor, sealed or not, left-joined to the members, and seals the window's unsealed rows. A window is
  a derived table with its own `LIMIT`, so no statement reads more than one batch of entries, however much of the table
  is sealed. The window's last `(recorded_at, id)` is saved as `sweep.cursor` after every window, whether or not it
  sealed anything, exactly as the row holds them, however long or malformed, so a row skipped as malformed at the end of
  a batch never stops sealing, and an interrupted sweep resumes there and never restarts at the beginning. A window
  shorter than a batch completes the sweep: `sweep.completed` is written and the cursor forgotten.
- A late row (one whose transaction committed after a later row was sealed, a queued record drained late, or a row
  recorded on a server whose clock runs behind) is still unsealed, so the next recent pass seals it while it is within
  the lookback, and the sweep seals it when it is not.
- A retry waits a random time up to 20 milliseconds after the first lost attempt, doubling after each, up to a second
  (`Sealer::JITTER_BASE_MS`, `JITTER_MAX_MS`).

## Anchors

`integrity.anchor.driver` chooses the anchor the package binds to `Contracts\CheckpointAnchor`: `null`
(`Enums\AnchorDriver::NONE`, the default) binds `Integrity\Anchors\NullAnchor`, which anchors nothing and cannot
discover, and `disk` (`AnchorDriver::DISK`) binds `Integrity\Anchors\DiskAnchor` on `integrity.anchor.disk`, or
`filesystems.default` when it is `null` or empty, under `integrity.anchor.path`. An application may bind its own.

- The contract has five answers: `name()`, 1 to 64 characters, kept in each seal's `anchor` column; `anchor()`, which
  keeps a summary and returns its receipt, a map of string keys to scalars or `null`; `confirms()`, whether a receipt
  still proves the anchor holds exactly that summary; `supportsDiscovery()`; and `latest()`, the newest
  `Integrity\AnchoredHead` (sequence and digest) or `null`, which throws when it cannot tell and never answers `null`
  for a history it could not read.
- `Integrity\Anchorer` runs after sealing in each `audit-log:seal` run, even one whose sealing failed, and is resolved
  only then, so an anchor that cannot be built from its settings stops anchoring alone. It anchors, in sequence order
  and at most `integrity.anchor.batch` a pass, the seals the anchor does not hold, by the anchor's own answer and never
  by the anchor columns, which the writer may edit: every seal after the anchor's head when it can report one, and
  otherwise every seal after the last one `anchor.last` records under the anchor's name; below that point, only a seal
  whose receipt was never written. Each read is by the unique sequence index or the anchoring index, so a pass never
  reads the seals already anchored. It anchors only a seal that verifies: the digest is recomputed from the stored
  fields and compared, and the signature is checked under the key the seal names; any other seal is refused and
  alarmed, and so, after the pass, is a seal stored at a sequence below 1. The receipt, at most 4096 bytes once encoded,
  is written with the anchor's name and the time.
- With `NullAnchor` a pass costs no statement and no call, and every seal is `unanchored`, which is informational.
- `DiskAnchor` writes the canonical encoding of the summary once, to `{path}/{log_id}/{sequence}-{seal_digest}.json`
  with the sequence padded to 20 digits, after a marker at `{path}/{log_id}/by-sequence/{sequence}` holding the digest.
  The marker comes first, so a second digest for a sequence is found with one read, even after a crash between the two
  writes, and the next anchoring of the same summary completes the object. A path that exists is read and compared,
  never written again, and nothing is ever deleted. A path that holds part of a write, as another anchorer still making
  it leaves it, is the anchor unavailable for now, never a conflict: only a whole marker or summary that differs is
  one. The receipt is the object's path and the SHA-256 of its bytes. The anchor holds one log and refuses a summary of
  another, so no path leaves `{path}/{log_id}`.
- Discovery reads the markers, which are authoritative and run unbroken from 1, since the anchorer writes them in
  sequence order and stops at its first failure. It probes whether a marker exists at doubling sequences, then halves
  the gap, in about two existence checks per doubling of the log and memory that does not grow with it, and never lists
  the disk. The head is the highest marker whose object is there, so a marker a crash left without its object is never
  the head and the one before it is; a marker that is not a digest is a partial write, and an object that is not the
  canonical summary is malformed, each a failure.
- A disk anchor's name is `disk:` and 16 hex characters of the SHA-256 of the disk's name and the path: its location.
  Moving the anchor anchors every seal again at the new location.
- The disk anchor's guarantees rest on the disk refusing to replace or delete what was written. On S3 that needs Object
  Lock in compliance mode with a retention period and a bucket policy denying version deletion: Object Lock protects
  versions, not keys, and a delete marker hides an object from an ordinary read. A new version hides an anchored object
  from an ordinary read, so the anchor also needs writes that cannot replace an existing object: credentials and a
  bucket policy under which the application can create an object but never write over one, or an equivalent write-once
  (WORM) store. These guarantees are conditional on that configuration, and the package has no S3 SDK dependency: the
  disk is any Laravel filesystem disk. A disk the application can overwrite or delete is no anchor, only a copy that
  someone who can reach it can change along with the log.

## Verification

`audit-log:verify` walks the whole log, or the seals from `--from` to `--to` by sequence, through `Integrity\Verifier`,
and prints one line per seal as it is verified, then one per finding of the run as a whole, then the summary; `--json`
writes each line as one JSON object, the summary last. Nothing is accumulated, so memory does not grow with the log.

- The run's clock is read once. The anchor's head is asked for first, when the anchor supports discovery, and the local
  head after it, so a remote head the local log does not reach is never a seal committed meanwhile; seals written after
  that head are skipped.
- `--from` and `--to` are seal sequences, validated against the head before anything is verified: a value that is not a
  sequence, a first seal after the last, an end beyond the head and a range of a log with no seal exit with `INVALID`
  (2), verify nothing and alarm nothing. A ranged run checks its first seal's link to the seal before it, and a missing
  one is a gap. A ranged run never establishes the integrity of the whole log: it says so, skips the whole-log checks
  below and records no completion.
- The walk reads seals in pages of 100 (`Verifier::SEAL_PAGE`) and expects the range's first sequence first, 1 on a
  complete run, then each next one through the range's last, so a deleted genesis seal, with its members and entries,
  is still a gap, and so are seals missing at the end of a range, or a range of which no seal is left: the coverage a
  run reports is never more than it read.
- The local head is the greatest sequence from 1. A seal row stored at a sequence below 1 is outside the chain, so no
  walk reads it and it is never the head; a complete run reports such rows as `sequence_gap`, and a member row whose
  seal is one of them as `orphan_member`, so an entry tied to a phantom seal is never hidden between unsealed and
  orphaned. The sealer never extends one, and the anchorer refuses one, whatever its anchor columns hold.
- `Integrity\SegmentVerifier` checks each seal: its sequence, that it can be read, its version and signer, its log id,
  its stored digest against the recomputed one, its signature under the key it names, the genesis rule and its link to
  the previous seal's recomputed digest. A link to a seal that cannot be read, of a later version or malformed, is
  broken: versions only increase, so a seal this release reads never follows one it cannot, and marking a seal
  unreadable never turns the deletion of its segment into anything short of `tampered`. Its members and their entries
  are then read in one statement, members left
  joined to entries, and streamed: each entry must exist, hold the HMAC the seal recorded and verify under its own key,
  the rows must be as many as `member_count`, and their ids and HMACs, sorted bytewise in PHP and never trusted to the
  database's order, must give `members_digest`. So members swapped between seals, an extra member and a removed one each
  fail.
- Anchoring comes from the anchor, never from the receipt. When discovery gave the anchor's head, the walk reaches it
  and the local seal there has the head's digest, the head settles every seal's anchoring with no further call: a seal
  up to the head is `anchored`, since the head's digest commits to the chain the walk checks link by link, and one after
  it is `unanchored`, since the anchor does not hold it. In a run that passes, every seal up to the head is therefore
  anchored; in one that fails on the chain, the break is the finding. Otherwise (a ranged run that ends before the
  head, a head the local log contradicts, or an anchor that cannot report its head) each receipt is put to the anchor:
  no anchor, no receipt, a receipt of another anchor or one the anchor does not confirm is `unanchored`. An anchor that
  fails, in discovery or when asked to confirm, is `unavailable` and is not asked again in that run, so an outage costs
  one timeout. Contradiction comes only from discovery or a conflict, never from a receipt, since the receipt columns
  are an unauthenticated cache: editing them changes nothing a run with discovery reports.
- A seal at the anchor's head that cannot be read has no digest to recompute, so its stored digest is compared with the
  head's: another is `contradicted`, with an `anchor_contradiction` finding of the run, never `unanchored`.
- A complete run also reports member rows of no seal in the chain (`orphan_member`) and unsealed entries: those older
  than `integrity.verify.max_unsealed_age_seconds` (90000 seconds, 25 hours, so a late row has a daily sweep to wait
  for) are `overdue_unsealed`, and those recorded more than `integrity.seal.lookback_seconds` ahead of the run's clock,
  which no seal takes while they stay ahead, are `future_unsealed`; each makes the log `incomplete`. The rest are
  pending, counted and never bad. The anchor's head is compared with the local seal at its sequence on every run.
- A complete run records `verify.last_full` with whether it passed at the strictness it ran at, and that strictness, so
  a strict run that failed on its anchoring alone never records a pass.
- A segment reports its most severe integrity status, then its first finding in the order of `Enums\Finding`, then the
  first bad id in member order. Every run prints the exact range it checked, the head it observed, the anchor's head,
  the segments in each status, those awaiting their first anchoring and, for a complete run, the unsealed entries.
- A run exits 0 when it passes and 1 when any segment or finding is `tampered`, `incomplete` or `unverifiable`, or when
  it stops. With `--strict` and an anchor configured it also fails on any segment short of `anchored`, on an
  `unavailable` or `contradicted` one, on an anchor whose `supportsDiscovery()` is `false`, since a truncated tail could
  not then be found, and on an empty remote while the local log holds a seal past the grace. A seal sealed within 15
  minutes of a strict run's start does not fail it while it waits for its anchoring (`Verifier::ANCHOR_GRACE_SECONDS`,
  900): sealing commits before it anchors, and `sealed_at` is signed, so the grace cannot be stretched without the key.
  The grace ends at the run's clock, so a seal dated after the run began, by a sealing server's clock running ahead or
  by a key holder, is never excused, nor is an `unavailable` or `contradicted` seal. With `NullAnchor`, `--strict`
  changes nothing.
- Every statement reads the writer, so a replica's lag never reads as a missing row, and a segment is read in one
  statement, so a prune committing beside it is seen whole or not at all.

| Integrity      | What it means                                                                                          |
|----------------|--------------------------------------------------------------------------------------------------------|
| `valid`        | Every check of the segment passed                                                                      |
| `pruned`       | Entries are missing and a valid prune record for exactly this seal accounts for them; it passes        |
| `incomplete`   | Entries are missing with no prune record, or unsealed entries are overdue or far ahead; it fails       |
| `unverifiable` | A check could not be made: something is malformed, of an unknown version or under an unknown key       |
| `tampered`     | The log was altered: a digest, a signature, the chain, the members or the anchor disagrees             |

| Anchoring      | What it means                                                                                  |
|----------------|------------------------------------------------------------------------------------------------|
| `anchored`     | The anchor's head commits to the seal, or the anchor confirms its receipt                      |
| `unanchored`   | The anchor does not hold it, or no anchor configured; informational unless `--strict`          |
| `unavailable`  | The anchor failed when asked, or failed earlier in the run, so the seal could not be confirmed |
| `contradicted` | The anchor holds another digest for the seal, or a head the local log does not reach           |

| Finding                | Integrity      | What it means                                                                     |
|------------------------|----------------|-----------------------------------------------------------------------------------|
| `seal_malformed`       | `unverifiable` | A seal row is not a well-formed seal, or its signature is malformed               |
| `seal_version`         | `unverifiable` | A seal is of an algorithm version or a signer this release does not read          |
| `seal_key`             | `unverifiable` | A seal is signed under a key the ring does not hold                               |
| `log_mismatch`         | `unverifiable` | A seal names another log than the one configured                                  |
| `seal_digest`          | `tampered`     | A seal's stored digest is not the digest of its fields                            |
| `seal_signature`       | `tampered`     | A seal's signature does not match its digest                                      |
| `genesis`              | `tampered`     | The first seal links to a previous one, or a later seal links to none             |
| `sequence_gap`         | `tampered`     | A seal the walk needs is missing, or a seal is stored outside the chain           |
| `chain_broken`         | `tampered`     | A seal does not link to the id and recomputed digest of a readable seal before it |
| `member_count`         | `tampered`     | A seal's member rows are not as many as it counts                                 |
| `members_digest`       | `tampered`     | A seal's member rows are not the members it sealed                                |
| `anchor_contradiction` | `tampered`     | The anchor holds another digest for a seal, or a seal it holds is missing locally |
| `anchor_conflict`      | `tampered`     | The anchor refused a seal because it holds another digest for the seal's sequence |
| `missing_tail`         | `tampered`     | The anchor holds seals past the local log's head, or holds a head of an empty log |
| `orphan_member`        | `tampered`     | A member row belongs to no seal in the chain                                      |
| `prune_record`         | `tampered`     | A prune record is forged, or does not bind the seal it names                      |
| `member_hmac`          | `tampered`     | An entry's stored HMAC is not the one its seal recorded                           |
| `entry_hmac`           | `tampered`     | An entry's HMAC does not match its content                                        |
| `prune_key`            | `unverifiable` | A prune record is signed under a key the ring does not hold                       |
| `entry_malformed`      | `unverifiable` | An entry is not a well-formed record, so it cannot be verified or sealed          |
| `entry_key`            | `unverifiable` | An entry is signed under a key the ring does not hold                             |
| `missing_entry`        | `incomplete`   | A sealed entry is missing, with no prune record to account for it                 |
| `overdue_unsealed`     | `incomplete`   | Entries older than `integrity.verify.max_unsealed_age_seconds` are still unsealed |
| `future_unsealed`      | `incomplete`   | Unsealed entries are recorded further ahead of the clock than the lookback        |

## Pruning And Erasure

Pruning ships with lifecycle; what it must do to keep the log verifiable is fixed here.

- A prune deletes entries only, of whole sealed segments, on the maintenance connection, and keeps every checkpoint and
  member row, so each seal's members digest can still be recomputed and the chain still runs through it. It commits
  atomically with its prune record.
- The prune record (`Integrity\PruneRecord`) binds `v` (1), `log_id`, `seal_id`, `seal_digest`, `member_count`, the
  operation's `operation_id`, its `pruned_at` and the `key_id` it is signed under. Its signature is the lower-case hex
  HMAC-SHA256 under the seal key of that ring key of the label `audit-log:prune:v1`, a line feed and the SHA-256 of the
  canonical encoding of every other field (`SealSigner::signPrune()`), so it is never a seal's signature.
- Verification asks `Contracts\PruneLedger::recordFor()` for a seal only when one of its entries is missing. Missing
  entries are `pruned` only with a record whose signature verifies and whose log id, seal id, seal digest and member
  count are the seal's. A record that fails is `tampered` with `prune_record`, and one under a key the ring does not
  hold is `unverifiable` with `prune_key`. The entries still present in a pruned segment are verified as any others.
- The default ledger, `Integrity\NullPruneLedger`, has pruned nothing, so a missing entry is always `incomplete`.
- Erasure destroys keys, never a row: an encrypted value's HMAC was computed over its ciphertext, so the row and its
  seal still verify once the key that could decrypt it is gone.

## Alerting And Progress

- `Console\IntegritySchedule` registers three runs on Laravel's scheduler: `audit-log:seal` on `integrity.seal.schedule`
  (`*/5 * * * *`), `audit-log:seal --sweep` on `integrity.seal.sweep_schedule` (`15 3 * * *`) and
  `audit-log:verify --strict --sweep-first` on `integrity.verify.schedule` (`45 3 * * *`), which sweeps first so an
  entry inserted late since the daily sweep, a replayed record say, is sealed before it can be found overdue. Each runs
  in the background, so it never holds up the application's tasks due in the same minute, and is kept from overlapping
  itself by a lock that lapses well inside its period (15 minutes for sealing, 23 hours for the daily runs). Each runs
  on one server only when the cache store the scheduler's locks are taken in, the one its mutex was given by
  `Schedule::useCache()`, or else the default store, has a driver every server shares (`redis`, `memcached`, `database`
  or `dynamodb`). A schedule that is `null` or empty registers nothing for that run.
- `audit-log:seal` takes a cache lock for at most 900 seconds when the default store can lock: `audit-log:seal` for the
  recent pass and `audit-log:seal:sweep` for the sweep, which are safe beside each other, so a long sweep never holds
  up the recent pass. A run that finds its own lock held prints "Another sealer holds the lock." and succeeds. The lock
  is only an optimisation: a store that cannot lock, or that fails, costs nothing but it, since sealing is safe beside
  another sealer.
- A failed or stopped verification, and in sealing a refused head, entries that cannot be sealed, an anchor conflict
  or a refused seal, dispatch `Events\IntegrityCheckFailed`, payload-free (the command, every integrity and anchoring
  status counted, the one failing condition of a seal run counted once, the finding, the first bad id when it is a
  lower-case UUID, the heads and whether the run was complete), and report an `Integrity\IntegrityCheckFailedException`,
  both through `Console\IntegrityAlarm`. A listener that fails is reported as it threw, and the alarm is still reported
  after it. A seal run stopped by anything else, a malformed anchor setting among them, is reported as an
  `Integrity\SealFailedException` alone. The events guide shows a listener.
- `Database\IntegrityProgress` keeps the progress in `integrity.state_table`, one named map per row with the time it was
  written: `seal.last_run`, `seal.last`, `seal.recent`, `sweep.cursor`, `sweep.completed`, `anchor.last`,
  `anchor.last_failure` and `verify.last_full`. Progress is operational, never evidence: verification reads none of
  it, sealing and anchoring read it only to start where they left off and fall back to the log without it, and a row
  lost or rewritten hides no change to the log.
- A run that never happens raises nothing, so the progress is what monitoring reads: no timer bounds the time an entry
  waits to be sealed or a seal waits to be anchored, since a stopped scheduler or a backlog extends it.

## Seams Left

- Carrying derived keys into a managed ring, and listing the ring's ids for reports.
- Lifecycle's prune and its journal, which implements `Contracts\PruneLedger`.
- The health snapshot, which reads the progress.
- The enterprise check profile, which requires the scheduled verification to be `--strict`.

## Implementation Anchors

- `src/Integrity/CanonicalEncoder.php`: `encode()`, `JSON_FLAGS`.
- `src/Integrity/RecordSigner.php`: `sign()`, `verifies()`, `capturedDigest()`, `SIGNED_COLUMNS`, `CAPTURED_COLUMNS`.
- `src/Integrity/KeyRing.php`: `signingKey()`, `key()`; `src/Integrity/IntegritySettings.php`: `validate()`.
- `src/Integrity/IntegrityKey.php`: `secret()`, `ID_PATTERN`, `MIN_SECRET_BYTES`;
  `src/Integrity/UnknownKeyException.php`: `forKey()`.
- `src/Records/RecordFinaliser.php`: `finalise()`; `src/Records/FinalisedRecord.php`.
- `src/Records/EnvelopeCodec.php`: `decode()`; `src/Delivery/Replayer.php`: `spill()`.
- `src/Integrity/SealEnvelope.php`: `membersDigest()`, `digest()`, `fromRow()`, `toRow()`, `LOG_ID_PATTERN`;
  `src/Integrity/SealSigner.php`: `sealKey()`, `sign()`, `verifies()`, `signPrune()`, `verifiesPrune()`,
  `DERIVATION_INFO`, `SEAL_LABEL`, `PRUNE_LABEL`.
- `src/Integrity/Sealer.php`: `seal()`, `sweep()`; `src/Integrity/CheckpointWriter.php`: `write()`, `writeWindow()`,
  `MEMBER_CHUNK`; `src/Integrity/SealCursor.php`, `src/Integrity/SealBatch.php`, `src/Integrity/SealResult.php`,
  `src/Integrity/SealSettings.php`, `src/Integrity/SealChainException.php`, `src/Integrity/SealContentionException.php`,
  `src/Integrity/SealFailedException.php`.
- `src/Contracts/CheckpointAnchor.php`; `src/Integrity/SealSummary.php`, `src/Integrity/AnchoredHead.php`;
  `src/Integrity/Anchorer.php`: `anchorPending()`, `MAX_RECEIPT_BYTES`; `src/Integrity/AnchorResult.php`.
- `src/Integrity/Anchors/NullAnchor.php`, `src/Integrity/Anchors/DiskAnchor.php`,
  `src/Integrity/Anchors/AnchorFactory.php`, `src/Integrity/Anchors/AnchorSettings.php`,
  `src/Integrity/Anchors/AnchorConflictException.php`.
- `src/Integrity/Verifier.php`: `verify()`, `SEAL_PAGE`, `ANCHOR_GRACE_SECONDS`; `src/Integrity/SegmentVerifier.php`:
  `verify()`, `boundary()`; `src/Integrity/SegmentReport.php`, `src/Integrity/RunFinding.php`,
  `src/Integrity/VerificationRange.php`, `src/Integrity/VerificationContext.php`, `src/Integrity/VerificationTally.php`,
  `src/Integrity/VerificationSummary.php`.
- `src/Integrity/Enums/IntegrityStatus.php`, `src/Integrity/Enums/AnchorStatus.php`, `src/Integrity/Enums/Finding.php`,
  `src/Integrity/Enums/AnchorDriver.php`.
- `src/Contracts/PruneLedger.php`; `src/Integrity/PruneRecord.php`, `src/Integrity/NullPruneLedger.php`.
- `src/Events/IntegrityCheckFailed.php`; `src/Integrity/IntegrityCheckFailedException.php`: `of()`, `stopped()`;
  `src/Console/IntegrityAlarm.php`: `raise()`, `report()`.
- `src/Console/SealCommand.php`: `LOCK`, `SWEEP_LOCK`, `LOCK_SECONDS`; `src/Console/VerifyCommand.php`;
  `src/Console/IntegritySchedule.php`: `SHARED_CACHE_DRIVERS`; `src/Console/IntegrityChecks.php`.
- `src/Database/IntegrityProgress.php`; `src/Database/IntegrityTables.php`.
- `database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php`,
  `database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php`,
  `database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php`.
- `config/audit-log.php`: `integrity`.

## Authoritative Tests

- `tests/Unit/Integrity/CanonicalEncoderTest.php` `testEncodesEachGoldenVectorByteForByte`, `testKeysSortBytewise`,
  `testANumericKeyMapStaysAMap`, `testAnEmptyObjectIsNotAnEmptyList`, `testListOrderIsKept`,
  `testNeverRepairsWhatItEncodes`, `testRefusesAFloat`, `testRefusesInvalidUtf8`
- `tests/Unit/Integrity/RecordSignerTest.php` `testTheGoldenEntrySignsByteForByte`,
  `testTamperingAnyColumnFailsVerification`, `testTamperingANestedPropertyOrAMicrosecondFailsVerification`,
  `testAnotherKeyIdInTheRingFailsVerification`, `testAKeyIdOutsideTheRingIsUnknown`, `testARetiredKeyStillVerifiesItsRows`,
  `testAnUnsupportedIntegrityVersionIsUnexpected`, `testAMissingColumnIsMalformedNeverNull`,
  `testAMalformedHmacIsUnexpected`, `testAStringPropertyEditedIntoABareNumberIsMalformedNeverVerified`,
  `testTheCapturedDigestLeavesOutTheFinalisationColumns`, `testVerificationNeverNormalises`
- `tests/Unit/Integrity/KeyRingTest.php` `testTheDefaultDerivesOneSigningKeyFromTheApplicationKey`,
  `testTheDerivedKeyIsStableForAFixedApplicationKey`, `testABase64ApplicationKeyIsDecodedBeforeDerivation`,
  `testARotatedApplicationKeyGetsANewKeyId`, `testPreviousApplicationKeysVerifyButNeverSign`,
  `testAnExplicitRingNeverFallsBackToTheApplicationKey`, `testAMalformedExplicitRingFailsClosedOnEveryCall`
- `tests/Unit/Integrity/IntegritySettingsTest.php` `testAMalformedRingFailsClosedNamingTheSetting`,
  `testAnEmptyCurrentKeyIdReadsAsNone`, `testNoMessageContainsASecret`
- `tests/Unit/Integrity/IntegrityKeyTest.php` `testRefusesAnIdTheColumnCannotHold`,
  `testRefusesASecretShorterThan32Bytes`, `testNoDumperEncodingOrExportShowsTheSecret`
- `tests/Unit/Records/RecordFinaliserTest.php` `testStampsTheClocksTimeAndSigns`,
  `testRecordedAtIsNeverBeforeTheActivityOccurred`, `testFinalisingTwiceAtOneInstantGivesTheSameBytes`
- `tests/Integration/Stores/StoredEntryRoundTripTest.php` `testAStoredRecordVerifiesAfterTheRoundTrip`,
  `testNestedPropertiesTheEngineReordersStillVerify`, `testUnicodeAndHostileTextStillVerify`,
  `testAnEditedStoredRowFailsVerification`
- `tests/Unit/Records/EnvelopeCodecTest.php` `testADecodedRecordVerifies`, `testATamperedValueIsASignatureMismatch`,
  `testAnUnknownKeyIsDistinct`, `testAnUnsupportedIntegrityVersionIsDistinct`,
  `testAnEnvelopeSignedWithARetiredKeyDecodes`
- `tests/Feature/Delivery/ReplayerTest.php` `testNeverResigns`, `testNeverFinalisesAgain`,
  `testAnUnknownKeyIsSkippedAndCounted`, `testAnUnsignedLineIsSkippedAndCounted`
- `tests/Integration/Delivery/SpillReplayEnginesTest.php` `testAReplayedRowVerifies`,
  `testALineUnderARemovedKeyReplaysOnceTheKeyIsBack`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testAnEnvelopeUnderARemovedSigningKeyIsFailedAndNeverResigned`
- `tests/Unit/Integrity/SealEnvelopeTest.php` `testTheGoldenMembersDigestIsReproduced`,
  `testTheGoldenSealCanonicalAndDigestAreReproduced`, `testTheSecondGoldenSealChainsOntoTheFirst`,
  `testMembersAreSortedBytewiseWhateverTheirOrder`, `testChangingAnyFieldChangesTheDigest`
- `tests/Unit/Integrity/SealSignerTest.php` `testTheDerivationAndLabelsArePinned`, `testTheGoldenSealKeyIsReproduced`,
  `testTheDerivedRingsSealKeyIsReproduced`, `testTheGoldenSignaturesAreReproduced`, `testARowHmacIsNeverASealSignature`,
  `testVerificationSelectsTheKeyByTheStoredId`, `testTheGoldenPruneRecordIsReproduced`, `testAForgedPruneRecordFails`
- `tests/Unit/Integrity/SealSettingsTest.php` `testAnEmptyLogIdIsTheSourceId`, `testRefusesAMalformedLogId`,
  `testRefusesAMalformedSchedule`
- `tests/Unit/Integrity/SealSummaryTest.php` `testTheCanonicalFormIsPinned`
- `tests/Unit/Integrity/PruneRecordTest.php` `testTheGoldenDigestIsReproduced`, `testEveryBoundFieldChangesTheDigest`
- `tests/Unit/Integrity/Enums/FindingTest.php` `testTheValuesArePinnedInPrecedenceOrder`,
  `testEachFindingMapsToItsStatus`
- `tests/Unit/Integrity/Enums/IntegrityStatusTest.php` `testSeverityOrdersTheStatuses`,
  `testOnlyIncompleteUnverifiableAndTamperedFail`
- `tests/Unit/Integrity/Enums/AnchorDriverTest.php` `testTheStoredValuesArePinned`
- `tests/Feature/Integrity/CheckpointWriterTest.php` `testSealsOnlyUnsealedRows`,
  `testSealsInRecordedOrderThenIdButMembershipIsWhatIsSealed`, `testRefusesToExtendAHeadWhoseDigestDisagrees`,
  `testRefusesToExtendAHeadOfAnotherLog`, `testExtendsAHeadSignedUnderARetiredKey`,
  `testTheCheckpointIsInsertedBeforeItsMembers`, `testNeverInsertsFromASelect`, `testNeverLocksWhatItSelects`,
  `testAMemberConflictFailsTheWholeAttempt`, `testAMalformedCandidateIsSkippedNotSealed`,
  `testAWindowReadsAtMostItsLimitWhateverIsSealed`
- `tests/Feature/Integrity/SealerTest.php` `testRefusesToRunInsideATransaction`,
  `testTheRecentPassStartsAtTheLookbackBeforeTheHead`, `testTheSweepResumesFromItsCursor`,
  `testACompleteSweepClearsItsCursor`, `testASweepWindowThatSealsNothingStillMovesTheCursor`,
  `testTheSweepFindsARowOlderThanTheLookback`, `testTheSettleDelayIsOptional`,
  `testASealNeverHoldsARowRecordedAfterTheSettleBound`, `testADuplicateIsRetriedFromAFreshHead`,
  `testEachRetryWaitsAJitteredBoundedDelay`, `testExhaustionThrowsContention`, `testALostConnectionIsNeverRetried`,
  `testNoSavepointIsEverUsed`, `testStopsAtMaxBatches`, `testAMixedKeySegmentSeals`,
  `testRotationBetweenSealsSignsEachWithItsKey`
- `tests/Integration/Integrity/SealerEnginesTest.php` `testSealsAndChainsOnEachEngine`,
  `testUuidOrderIsNeverAHighWaterMark`, `testATransactionCommittingOutOfOrderJoinsALaterSeal`,
  `testSealingReadsTheWriter`
- `tests/Integration/Integrity/ConcurrentSealersTest.php` `testTwoSealersInSeparateProcessesSealEveryEntryOnce`,
  `testALosingSealerRetriesFromTheNewHead`, `testSealingNeverBlocksRecordingOnMySqlAndPostgres`
- `tests/Integration/Integrity/LateArrivalsTest.php` `testARowOlderThanTheLookbackWaitsForTheSweep`,
  `testAQueuedRecordDrainedLateJoinsALaterSeal`
- `tests/Integration/Integrity/SealCrashBoundariesTest.php` `testACrashBetweenMemberChunksLeavesNothing`,
  `testACrashMidSweepResumesFromTheSavedCursor`
- `tests/Feature/Integrity/Anchors/DiskAnchorTest.php` `testWritesTheGoldenObjectAtTheGoldenPath`,
  `testAnchoringTheSameSummaryAgainReturnsTheSameReceiptAndWritesNothing`,
  `testADifferentDigestForAnAnchoredSequenceConflicts`, `testTheMarkerIsWrittenBeforeTheObject`,
  `testAMarkerWrittenBeforeACrashStillRefusesAnotherDigest`, `testNeverOverwritesOrDeletes`,
  `testAReplayedReceiptDoesNotConfirm`, `testTheLatestIsTheHighestSequence`, `testDiscoveryProbesMarkersAndNeverLists`,
  `testAPartialWriteIsUnavailableNotAConflict`, `testEveryPathStaysInsideTheNamespace`, `testItsNameIsItsLocation`
- `tests/Unit/Integrity/Anchors/NullAnchorTest.php` `testItCannotDiscover`
- `tests/Feature/Integrity/AnchorerTest.php` `testTheNullAnchorCostsNoStatement`,
  `testAnUnavailableAnchorIsRecordedNotReported`, `testARemoteSuccessWithAFailedLocalWriteRecoversWithTheSameReceipt`,
  `testAConflictStopsThePass`, `testATamperedSealIsNeverAnchored`, `testMovingTheAnchorReanchorsEverySeal`,
  `testOnlyTheAnchorColumnsAreWritten`, `testReceiptColumnsOnAFreshSealNeverKeepItFromTheAnchor`,
  `testASealOutsideTheChainIsRefusedAfterThePass`, `testAPassReadsByTheSequenceAndAnchoringIndexes`
- `tests/Integration/Integrity/AnchorCrashBoundariesTest.php`
  `testACrashAfterTheRemoteWriteBeforeTheReceiptRecoversWithTheSameReceipt`,
  `testACrashBetweenTheMarkerAndItsObjectStillRefusesAnotherDigest`
- `tests/Feature/Integrity/SegmentVerifierTest.php` `testTheMostSevereFindingWins`,
  `testAnUnexpectedFirstSequenceIsAGap`, `testTheChainIsOverRecomputedDigests`,
  `testALinkToASealThatCannotBeReadIsBroken`, `testASealDatedAfterTheRunIsNotAwaiting`,
  `testTheAnchorsHeadSettlesAnchoringWithNoCall`,
  `testMembersSwappedBetweenSealsAreTampered`, `testAValidPruneRecordIsPruned`, `testAForgedPruneRecordIsTampered`,
  `testPruningNeverExcusesABadSignature`, `testPruningNeverExcusesABrokenChain`,
  `testPruningNeverExcusesAnAnchorContradiction`, `testAReplayedReceiptIsUnanchored`,
  `testOneStatementReadsTheMembersAndTheirEntries`, `testTheMemberOrderIsSortedNotTrusted`
- `tests/Feature/Integrity/VerifierTest.php` `testADeletedGenesisSealIsTampered`, `testAMissingBoundarySealIsAGap`,
  `testAFailingAnchorIsAskedOnce`, `testAnEmptyRemoteWithALocalLogIsUnanchored`, `testAnEmptyRemoteAndAnEmptyLogAgree`,
  `testARemoteHeadBeyondTheTailIsTampered`, `testTailTruncationIsFoundWithLocalReceiptsCleared`,
  `testARangedRunIsNotComplete`, `testARangedRunSkipsTheWholeLogChecks`, `testSealsAfterTheStartHeadAreSkipped`,
  `testAnOverdueUnsealedRowIsIncomplete`, `testAYoungUnsealedRowIsPendingNeverBad`,
  `testKeyRotationBetweenSealsVerifies`, `testAFullRunRecordsItsCompletion`,
  `testAStrictRunRecordsWhetherItPassedStrictly`, `testAMissingLastSealOfARangeIsAGap`, `testARangeWithNoSealIsAGap`,
  `testASealOutsideTheChainIsFound`, `testAnUnsealedEntryFarAheadOfTheClockIsAFinding`,
  `testAnUnreadableSealAtTheAnchorsHeadIsComparedByItsStoredDigest`, `testTheAnchorsHeadSettlesAnchoringWithOneCall`,
  `testNothingIsAccumulated`, `testEveryQueryReadsTheWriter`
- `tests/Unit/Integrity/VerificationSummaryTest.php` `testStrictExcusesOnlyASealWithinTheGrace`,
  `testStrictFailsWithoutDiscovery`, `testStrictChangesNothingWithTheNullAnchor`
- `tests/Feature/Console/VerifyCommandTest.php` `testTheCoverageIsAlwaysPrinted`,
  `testARangedRunSaysItIsNotTheWholeLog`, `testRefusesARangeBeyondTheHead`,
  `testATamperedLogFailsNonZeroNamingTheFirstBadId`, `testStrictFailsOnAnUnanchoredSegmentWhenAnAnchorIsConfigured`,
  `testStrictPassesBesideASealNotYetAnchored`, `testUnanchoredIsInformationalWithTheNullAnchor`,
  `testAStoppedRunAlarms`, `testAMalformedAnchorSettingAlarms`, `testSweepFirstSealsALateEntryBeforeVerifying`,
  `testOutputHoldsNoValueOfAnEntry`
- `tests/Feature/Console/SealCommandTest.php` `testAHeldLockSkipsTheRun`, `testTheSweepHoldsItsOwnLock`,
  `testACacheThatFailsDoesNotStopSealing`, `testAnUnavailableAnchorWarnsAndStillSucceeds`,
  `testAMalformedAnchorSettingStillSeals`, `testAConflictAlarmsAndFails`, `testASkippedEntryAlarms`
- `tests/Feature/Console/IntegrityAlarmTest.php` `testAListenerThatFailsIsReportedAndHidesNothing`,
  `testAnIdThatIsNoUuidNeverReachesAListener`
- `tests/Feature/Console/IntegrityScheduleTest.php` `testTheThreeRunsAreScheduledByDefault`,
  `testEachRunCanBeTurnedOff`, `testOnOneServerOnlyOnASharedCache`, `testTheSchedulersStoreDecidesOneServer`,
  `testEveryRunIsInTheBackground`, `testEachRunIsWithoutOverlapping`,
  `testAMalformedScheduleSchedulesNothingAndIsReported`
- `tests/Feature/Integrity/IntegrityAlertingTest.php` `testTheEventIsPayloadFree`, `testEveryMapHoldsEveryStatus`
- `tests/Integration/Database/IntegrityProgressTest.php` `testAMalformedValueReadsAsAbsent`,
  `testReadsAndWritesTheWriter`
- `tests/Integration/Integrity/VerifyConcurrencyTest.php` `testAPruneCommittingDuringVerificationIsNeverHalfSeen`,
  `testSealsCreatedDuringVerificationAreSkipped`, `testAStrictVerificationBesideASealRunPasses`
- `tests/Integration/Integrity/PruneBoundariesTest.php` `testACrashBeforeThePruneCommitsLeavesTheSegmentValid`,
  `testACommittedPruneIsPruned`
- `tests/Unit/Integrity/NullPruneLedgerTest.php` `testNothingIsEverPruned`
- `tests/Feature/Integrity/TamperingTest.php` `testAJointSealAndMemberRewriteWithoutTheKeyIsTampered`,
  `testAJointRewriteWithTheKeyBreaksTheChainToTheNextSeal`, `testEditingTheAnchorColumnsChangesNothing`,
  `testTailTruncationWithLocalReceiptsClearedIsTampered`, `testAPreSealDeletionIsUndetectable`,
  `testAPhantomSealAtSequenceZeroIsFound`, `testAFarFutureEntryIsNeverPendingForGood`,
  `testADeletedSealAtTheEndOfARangeIsAGap`, `testMarkingASealUnreadableNeverHidesItsDeletedSegment`
- `tests/Unit/Integrity/IntegritySensitiveParametersTest.php` `testEveryKeyOrRowParameterIsMarkedSensitive`,
  `testNothingChainsAFailure`, `testNothingReadsAFailuresText`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheIntegrityNoteHasARowForEveryStatusAndFinding`

## Change Triggers

Update this note when any of the following change:

- a rule of the canonical encoding, or its JSON flags
- the signed or captured columns, or their order
- the integrity version, or the versions verification supports
- the derivation, its info string or the derived key's id
- the key id grammar or the shortest secret
- what verification answers, or which exception it raises
- what a replay verifies, or how a removed key is handled
- the seal envelope's fields, the members digest or the log id grammar
- the seal key's derivation, its info string or a signature's label
- how the recent pass or the sweep selects entries, or what a seal attempt retries
- the anchor contract, the disk anchor's paths, marker or receipt, or what its guarantees rest on
- an integrity or anchoring status, a finding, or the status a finding gives
- what a strict run fails on, or the anchoring grace
- the prune record's fields or what a prune keeps
- the schedule, the cache lock, the event or the progress names
