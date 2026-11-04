# Privacy

## Purpose

This note records how an owner's personal data is sealed, read and erased: the keys the package keeps for each owner
and how they are wrapped, created, rotated and destroyed, the envelope a field is sealed in and what binds it to its
entry, the key uses that find an owner's entries, the grant that lets a viewer read a sealed field, the erasure that
destroys an owner's keys, what a database restore brings back, what an erasure does not reach, and what each store the
package writes holds. An audit log is personal data held about everyone it names, and erasure here is the destruction
of keys, never of rows, so the integrity of the log and the right to erasure both hold. Two guarantees are stated
apart, here as everywhere. Database credentials can still destroy keys, key uses and markers; the package's
cryptographic evidence makes unauthorised destruction, substitution or restoration detectable, never impossible. What
none of this promises is in `threat-model.md`; how the trail is read is in `reading.md`; how an erasure is journalled
beside the other maintenance operations is in `lifecycle.md`.

## Invariants

- A key unit is the owner, the record's tenant and the definition's category, so materially different obligations
  never share a key, and a tenant-local id reused across tenants never names the same unit (`Keys\KeyUnit`). A hold on
  one category of an owner's records leaves the owner's other units erasable: a hold is not a blanket Article 17
  exemption for every fragment of a person, and the package records the basis it is given and never decides legal
  necessity.
- The package seals by default. `Privacy\SubjectKeyEncrypter` is the bound `Contracts\FieldEncrypter`, so a field a
  definition encrypts, an owned note and an address under the `encrypt` IP mode are sealed under their owner's key
  with nothing for the application to bind. `Privacy\NoFieldEncrypter` is the explicit choice never to encrypt: every
  such value is then dropped and diagnosed, and never stored in plaintext.
- No key outlives one operation in memory. An encrypter is built for one record's minimisation and holds the data keys
  of that entry alone; a page's keys live in the reader's call for that page; no singleton holds a data key, an
  unwrapped key or a wrapping key's secret, and the encrypter and the reader are bound afresh for each resolution. An
  erasure that commits between two records, or two pages, is seen by the second.
- The writer never updates a key. The storage connection's writer inserts keys, on the key session, and key uses, with
  their entries, and nothing else into the key tables; every update of a key (a tombstone, a rewrap, a rotation) and
  every owner marker is written on the maintenance connection inside a `Lifecycle\MaintenanceTransaction`, journalled.
- Keys are read on the storage connection's writer by the encrypter, the reader, an erasure and verification, so a
  replica lagging an erasure never decrypts what the erasure revoked.
- Every destructive decision reads authenticated state inside the lifecycle lock: the holds of the journal chain it
  verified, key rows whose signatures it verifies and entry rows whose HMAC it verifies. Nothing read before the lock
  decides a destruction, and an erasure refuses what it cannot authenticate.
- The journal row commits with what it describes; the activity record follows the commit. `audit_log.subject_erased`,
  `audit_log.keys_reinstated` and `audit_log.keys_rewrapped` are written by `Lifecycle\LifecycleRecorder` once the
  operation's transaction has committed, and a recording failure never undoes the operation and shows as
  `recorded: false`.
- Erasure destroys keys; it erases no reference, no retained value and no row. Every entry, seal and journal row still
  verifies once a key is gone, because an entry's HMAC was computed over its ciphertext.
- No store is claimed to hold no personal data. A keyed owner fingerprint, references, authority ids, hold scopes and
  read filters are personal data while they can be linked to a person, and Stores And What They Hold lists each store
  with what it holds and why.

## Success Path

1. A record is captured; the pipeline reads the clock once and mints the entry's id from it before anything is
   minimised.
2. Minimising seals the address, the note and the encrypted fields, in that order, each as typed plaintext at its path,
   through `SubjectKeyEncrypter`, which looks every unit of the record up in one statement and creates a missing one
   on the key session.
3. `DatabaseAuditStore` inserts the entry and its key uses together, or the outbox or a spill holds the record sealed
   until a drain or a replay stores it the same way.
4. A viewer whose scope is granted `revealingEncryptedFields()` reads a page: each row's HMAC is verified, every sealed
   field of the page is read in one call to `Privacy\SubjectKeyFieldReader`, and the read's record counts what each
   field showed.
5. An operator erases an owner with `AuditLog::lifecycle()->erase()` or `audit-log:erase`: the owner's keys are
   checked against the replayed holds and preservation, journalled and tombstoned in one maintenance transaction, and
   the owner is marked erased, so every field ever sealed for the owner reads `erased`.
6. The operator's procedure carries the erasure across the estate, and `audit-log:verify` keeps proving that every key
   destroyed was destroyed by a journalled erasure and that none came back.

## Failure / Edge Cases

- An owner absent from the record, an owner whose latest marker records an erasure, and an owner the key store cannot
  serve are alike to the record: the field is dropped and counted as an omission, with no reason. The omission log
  holds paths and a count, never reasons, and a reason naming an erasure in every later record about the owner would
  itself disclose that the owner was erased.
- A key store or wrapper failure while sealing is contained by `Privacy\EnvelopeSealer`, which reports it once naming
  `SubjectKeyEncrypter` alone, and the field is dropped; nothing is stored in plaintext.
- A creation that waits past its owner's lock is a `Keys\OwnerLockTimeoutException`, which names the wait alone; the
  creation is rolled back whole and the field dropped.
- A live key whose row fails its signature, or names a signing key the ring does not hold, is never used to seal: the
  lookup throws, and the record's encrypted fields are dropped.
- A row that fails its HMAC under a revealing scope shows every envelope it holds `unreadable`, and none reaches the
  reader. A reader that throws, or answers another count, costs every field of the page, `unreadable`, reported once
  naming its class.
- A key that is null or erased without a verified erasure row listing it reads `unreadable`, never `erased`, and
  verification reports it `key_destroyed_unjournalled`.
- An erasure is refused, writing nothing, with an `ErasureRefusedException` whose reason is one of
  `Lifecycle\Enums\ErasureRefusal`: `blocked` (a hold, preservation or an unverified entry blocks a key, and the erasure
  was not asked to go ahead in part), `pending_delivery` (the outbox holds rows older than the erasure, not accepted),
  `unsupported_encrypter` (the bound encrypter keeps its keys elsewhere), `key_unverifiable` (a key row of the owner
  fails its signature or names an unknown signing key) or `too_many_keys` (more than 10,000 live or superseded keys).
  A broken journal refuses it with a `JournalBrokenException`, and a tombstone that changes another number of keys
  than it names rolls the whole erasure back.
- A reinstatement of an owner who is not erased is refused `not_erased`; one whose latest marker names no row of the
  verified chain is refused as a broken journal.
- `holdingDataOf()` with an encrypter other than the package's throws a `\LogicException` naming the bound class, and
  the verification's key store section reports itself skipped; `key_use_missing` still runs.

## Keys

- `privacy.subject_keys_table` (`audit_log_subject_keys`) holds one row per unit generation. Its `id` is a lower-case
  UUID version 7 of the instant the key was created, which every envelope sealed under it names as `k`; it is opaque
  and never derived from the owner. Its `unit` is the lower-case hex SHA-256 of the canonical encoding of
  `[owner_type, owner_id, tenant_type, tenant_id, category]`, unkeyed, since the columns beside it are plain, and the
  table is unique on `unit` and `generation`.
- A key is in one of three states (`Integrity\Enums\KeyState`): `live` (wrapped, it seals and opens), `superseded`
  (wrapped, it opens only) and `erased` (no wrapped key, and it never reopens).
- A data key is `random_bytes(32)`, stored only wrapped: AES-256-GCM through `Contracts\KeyWrapper`, a fresh 12-byte
  nonce and a 16-byte tag, as `base64url(nonce ‖ ciphertext ‖ tag)`, 80 characters under `Keys\LocalKeyWrapper`. The
  wrap's additional data is the canonical encoding of `{d: 'sinemacula/audit-log:wrap:v1', generation, k, unit,
  wrap_key_id}`, so a wrapped key moved to another row, or beside another wrapping key id, does not unwrap.
- A key row is signed: `hmac` is the lower-case hex HMAC-SHA256 of the label `audit-log:subject-key:v1`, a line feed
  and the SHA-256 of the canonical encoding of `{v: 1, id, owner_type, owner_id, tenant_type, tenant_id, category,
  unit, generation, created_at, key_id}`, under `hash_hkdf('sha256', $secret, 32, 'sinemacula/audit-log:subject-key:v1',
  '')` of the integrity ring's signing key, whose id is `key_id` (`Integrity\SubjectKeySigner`). The mutable columns,
  `state`, `wrapped_key`, `wrap_key_id` and `erasure_id`, are not signed: the wrap context binds the wrapped key, and
  the journal binds the state.
- The wrapping ring is `privacy.keys`, key ids to secrets of at least 32 bytes or `base64:` and their encoding, with
  `privacy.current` naming the key that wraps; both are set or neither. Without them, `app.key` and each of
  `app.previous_keys` are derived by `hash_hkdf('sha256', $key, 32, 'sinemacula/audit-log:subject-wrap:v1', '')`, under
  an id of `d-` and the first 16 hex characters of a fingerprint of the derived secret: the key derived from `app.key`
  wraps, and the others only unwrap what they wrapped before a rotation. An explicit ring never wraps under `app.key`,
  and a malformed one never falls back to it; it keeps the keys derived from `app.key` and each of `app.previous_keys`
  to unwrap only, so the keys wrapped before it was set still unwrap and `audit-log:rewrap` moves them onto
  `privacy.current`. `audit-log:check` compares the `wrap_key_id` of every live and superseded key with the ring's ids,
  unwrapping nothing, and reports a key wrapped under a key the ring does not hold. The derivation gives domain
  separation, not independence from `app.key`: anyone holding `app.key` holds the derived wrapping keys too, and a
  wrapping key that must outlive or outlast `app.key` belongs in `privacy.keys`.
- A key is created the first time a record needs it, on `Keys\KeySession`: a connection of its own to the storage
  connection's writer, built from that connection's resolved configuration and purged after the creation, so a key
  commits on its own and never disappears with a host transaction that rolls back while a spill, the outbox or an
  in-flight write already holds ciphertext under it. Where a second connection could not see or write what the
  storage connection does (in-memory SQLite, the testing manager's base transaction, and SQLite whenever the storage
  connection is inside a transaction) the storage connection itself is the session, so on SQLite a key created inside
  a host transaction rolls back with it, and the fields sealed under it then open under no key.
- A creation and an erasure or a reinstatement of the same owner exclude each other through the owner's advisory lock
  (`Keys\OwnerLock`), never a row lock, since an owner's first key has no row to lock: PostgreSQL's
  `pg_advisory_xact_lock()` inside the creation's transaction, its wait bounded by `set local lock_timeout = '10s'`;
  MySQL's `get_lock()` for at most 10 seconds, released once the transaction has ended; and on SQLite none, because
  its one writer serialises the transactions. The order is always the lifecycle lock, then the owner's. The marker
  read, the unit's live key and the insert are one transaction on every engine.
- An owner marker (`Keys\OwnerMarker`), in `privacy.owner_erasures_table` (`audit_log_owner_erasures`), records each
  erasure or reinstatement of an owner (`Integrity\Enums\MarkerTransition`: `erased` or `reinstated`) under its journal
  row's id, at its sequence, with the generation floor. No key is created while the owner's latest marker is `erased`,
  and a key is created at the larger of the floor and the unit's largest generation, plus one, so an erased
  generation never reopens. A marker is not verified on its own: a forged or missing one can only refuse or allow a
  creation, and a key created for an erased owner is `key_restored`.
- Two creations racing past every lock are settled by the unit's unique index: the loser re-reads the unit's live
  key, verified, and seals under it. A live key that landed while a creation waited for the lock is returned, never
  doubled.
- `audit-log:rewrap` (`AuditLifecycle::rewrap()`) wraps every live or superseded key held under another wrapping key
  again under the current one, in batches of `privacy.rewrap_batch` (500 by default, from 100 to 10000), each a
  maintenance transaction that changed or skipped a key journalled as one `rewrap` row; a key that fails its signature
  or its unwrapping is skipped and named, by its id only when that is a UUID. Every candidate is unwrapped, one already
  under the current key included, and a new wrapped key must unwrap to the same data key before it replaces the stored
  one, the only copy; key creation checks a new key the same way before inserting it. With `--rotate` it also supersedes
  every live key, so the next write of each unit opens its next generation: rotation is not rewrap. The run's status is
  `Lifecycle\Enums\RewrapStatus`: `complete`, or `partial` when it skipped a key.

## Encryption

- A field is sealed under a field key derived from its unit's data key and the entry id,
  `hash_hkdf('sha256', $dataKey, 32, 'sinemacula/audit-log:field-key:v1', $entryId)`, so a derived key seals only the
  fields of one entry, each under its own random nonce. That bounds the use of each key by construction, far below
  what AES-GCM allows under one key with random nonces, and rotation is on demand.
- The envelope is `{v: 1, k: <key row id>, c: base64url(nonce ‖ ciphertext ‖ tag)}`: AES-256-GCM, a 12-byte nonce
  drawn by `random_bytes()` inside the call and never a parameter, and a 16-byte tag (`Privacy\FieldCipher`). `c` is
  strict base64url with no padding whose re-encoding is the stored text, of 30 to 1052 decoded bytes.
- The additional data is the canonical encoding of `{d: 'sinemacula/audit-log:field:v1', entry, k, log, path, v}`,
  where `log` is the integrity log's id and `path` a JSON list: the column (`properties`, `context` or `ip`), then each
  list index as an integer at the element's stored index and each map key as PHP keys it, an integer from 0 as that
  integer and any other key as a string (`Privacy\EncryptedField::segment()`), so a member's path is the same whether
  minimisation leaves its container stored as a map or as a list, such as
  `["properties","card","last4"]`, `["properties","_audit","note"]` or `["ip"]`. An envelope copied to another entry,
  path or log reads `unreadable`, and a row edited to hold one fails its HMAC first.
- The entry id is minted before minimisation and given to it, so every value is sealed for the entry that stores it.
  `Privacy\FieldContext` carries the entry id, the path, the log id, the record's tenant and category and every owner
  the record seals for, so the first field of a record looks every unit up at once, and a custom encrypter may batch
  the same way.
- Plaintext is typed: the canonical encoding of the value for every type, so the string `"true"` and the boolean
  `true` differ (`Privacy\TypedPlaintext`). It is at most 1024 bytes after encoding: a string is cut to the longest
  prefix, on a character boundary, whose encoding fits, and any other value over the limit is dropped and diagnosed
  without calling the encrypter.

## Key Uses

- `privacy.key_uses_table` (`audit_log_key_uses`) holds one row for each distinct key an entry's envelopes name,
  `(key_id, entry_id)`, for every `k` that is a canonical lower-case UUID, whatever encrypter made it
  (`Records\EnvelopeKeys`, which finds exactly what the projector reads as an envelope). A value the application shaped
  as an envelope never reaches a stored record: minimisation removes every value of the properties and the context
  that is exactly an envelope, logged under its masked path, before anything is sealed, as an import drops one, so every
  envelope an entry holds is one its own sealer made, and no key use links an entry to an owner's key that sealed
  nothing in it, nor lets `holdingDataOf()` or an erasure's blocks name it.
- `DatabaseAuditStore` writes an entry with envelopes and its key uses together, in one transaction or a savepoint
  inside a host's; an entry with no envelope keeps its single insert. The outbox drain and the spill replay store
  through it, and an import inserts each chunk's key uses with its entries, on the storage writer.
- Key uses are an append-only, derived index: no role may update or delete one, the documented triggers refuse both,
  and a prune leaves them, since an orphan names an entry no longer there and blocks nothing. `audit-log:verify`
  proves them complete: a verified entry whose envelope names a key with no key use of that entry is
  `key_use_missing`. `audit-log:keys --rebuild-uses` (`Keys\KeyUseRebuilder`) only adds, from entries whose HMAC
  verifies, and never removes a row.
- `AuditTrail::holdingDataOf()` selects the entries holding a fragment an owner's keys sealed: an `EXISTS` over the key
  uses joined to the owner's keys, inside the viewer's scope like every filter, and an owner already erased is still
  found, so an investigator can show what the erasure reached.

## Reading

- `AccessScope::revealingEncryptedFields()` is the grant to read sealed fields. It is off on every starting scope,
  survives every narrowing, is part of the scope's normalised form, its fingerprint and the cursor's binding, and a
  denied scope stays denied and reveals nothing. The access policy decides it per viewer and purpose. The grant
  reveals every encrypted field of every entry the scope sees, whoever owns it, and is not an owner-specific
  projection: `holdingDataOf()` selects entries, and the other owners' fragments those entries hold are reviewed
  before anything is disclosed.
- Without the grant, every envelope is shown `encrypted` and no reader is asked. With it, `Querying\EntryProjector`
  verifies each row's HMAC with `Integrity\RecordSigner` first: a row that fails, or whose signing key the ring does
  not hold, shows every envelope `unreadable`. Only the projector builds a `Privacy\EncryptedField`, whose constructor
  is private, and only from a verified row, so no caller can hand a reader an envelope.
- The fields of a page are read in one call, `Contracts\FieldReader::readAll()`. `SubjectKeyFieldReader` reads the
  page's keys by id in one statement on the writer, verifies each key row's signature, and answers each field its typed
  value, `erased` or `unreadable` (`Privacy\Enums\FieldState`). A key is `erased` only when the erasure row its
  `erasure_id` names, read by id in one more statement only when the page holds an erased key, is a verified `erasure`
  of this log listing the key as destroyed. Anything else that does not open is `unreadable`.
- A revealing page's record keeps `reveal` and `fields`, the count of fragments it showed `encrypted`, `erased`,
  `revealed` and `unreadable`, never a value. Counts and exports never decrypt, and an export stays canonical
  evidence, its envelopes as stored. `Privacy\SealedFieldReader`, which answers `encrypted`, remains for an
  application that never decrypts in PHP.
- A decryption already returned cannot be recalled. An erasure's commit is the point after which no read reveals the
  owner's fields; a page read before it has shown what it showed, and what a viewer did with it is beyond any record.

## Erasure

- `AuditLog::lifecycle()->erase()`, and `audit-log:erase`, erase an owner (`Lifecycle\Eraser`). With the package's key
  store in use (`Privacy\KeyStoreUse`: the bound encrypter is exactly `SubjectKeyEncrypter` or `NoFieldEncrypter`), the
  installation is confirmed and one maintenance transaction runs: the lifecycle lock, the journal verified and its
  holds replayed, the owner's lock, the owner's latest marker, then the owner's keys, each verified.
- The outbox rows created before the erasure started, failed ones included, are counted after the lock: any refuses
  the erasure `pending_delivery`, unless `--pending` accepts them, since every field of the owner they hold is erased
  with the key. The outbox is sealed under `app.key`, so its owners cannot be told apart without decrypting every
  row, and a hold protects a record only once it is stored.
- Each live or superseded key's entries are read through its key uses, in keyset pages of 1,000, each entry's HMAC
  verified, and decide its blocks (`Lifecycle\ErasureBlocks`): `held:<hold id>` for an active hold of the verified
  chain whose scope matches an entry, `preserved:<category>` for an entry that occurred at or after the erasure's UTC
  midnight less the days its category and tenant are preserved, and `unverified` for an entry that fails its HMAC or
  names a signing key the ring does not hold, since what it says cannot decide a destruction. Any block refuses the
  whole erasure, all or nothing, unless `--partial` asks to destroy the unblocked keys and report the rest.
- An erasure that goes ahead appends an `erasure` row naming the authority, the owner's fingerprint under the ring's
  signing key and that key's id (`Integrity\OwnerFingerprint`), the new generation floor, whether it went ahead in
  part, the outbox rows it accepted, each destroyed key with its state, HMAC, wrapped key digest and wrapping key
  before and `erased` after, each kept key with its reasons, and `entries_affected`, the distinct entries the
  destroyed keys sealed. The destroyed keys are tombstoned, `erased` with no wrapped key and the row's id as their
  `erasure_id`, by an update whose affected count must equal the keys it names, and an `erased` marker is inserted
  under the row's id. An owner with no key is still marked and journalled; an owner already erased with no live or
  superseded key is a no-op.
- The result's status is one of `Lifecycle\Enums\ErasureStatus`: `complete`, `partial` or `already_erased`. A partial
  erasure marks the owner erased: its kept keys go on sealing what their units already seal, since their obligation
  stands, and no other unit or generation of the owner is created until a reinstatement; a rotation supersedes a kept
  key like any live one.
- An erasure linearises at its commit. Ciphertext under an erased key that lands later, from the outbox, a spill, a
  replay or an in-flight capture, is erased by construction, since its key is gone.
- `AuditLog::lifecycle()->reinstate()`, and `audit-log:reinstate`, reinstate an erased owner (`Lifecycle\Reinstater`),
  journalled as a `reinstate` row with a `reinstated` marker at the same floor. It creates no key: the owner's next
  write creates the generation above the floor, and the keys the erasure destroyed stay destroyed.
- An erasure has two outcomes, named apart. Revoked in the live store is what the package does; erasure complete is
  the operator's procedure across the estate: database backups, WAL and binlogs expiring past the erasure, replicas,
  exports, logs and error trackers, every destination's own store such as a SIEM, and the pending deliveries it
  accepted. `audit_log.subject_erased` reaches the destinations like any package record, so each can apply the
  erasure to what it holds.

## Restores

- A database restored from before an erasure brings the erased keys back, wrapped. Under `LocalKeyWrapper` the
  wrapping keys live in the application's configuration, beside the database, so restoring both restores what the
  erasure destroyed. A `Contracts\KeyWrapper` over an external key service whose wrapping keys are destroyed outside
  the database's backups is what lets an erasure reach a backup.
- `audit-log:verify` reports a key that is live or superseded while its owner's latest verified transition is an
  erasure that did not keep it, or that is at or below the floor of a reinstated owner, as `key_restored`, and a key
  destroyed without a verified erasure row listing it as `key_destroyed_unjournalled`; it also reports `key_missing`,
  `key_substituted` and `key_unverifiable` (`Integrity\KeyStoreVerifier`, on runs of the whole log). The journal binds
  a key's state, which its signature leaves out: a key whose state, wrapping key or wrapped key is not what its latest
  verified `rewrap` row left, or that is superseded with no rewrap listing it, is `key_substituted`, so a key flipped
  between `live` and `superseded` outside a rewrap, or restored to its row from before a rotation, is found.
- The external registry of erasures is the seal anchor: the journal head is sealed and anchored, so a restore older
  than an anchored erasure contradicts the anchor. `audit-log:check` finds a full restore through it, the anchor's
  latest sequence beyond the local latest seal or another digest at the local head's sequence, and reports it, with
  any restored or unjournalled key, as a problem until a verified `restore_reconciled` row names that anchored
  sequence and digest. Without an anchor that discovers, a full restore cannot be found.
- `audit-log:erase --reapply=<file>` erases again every owner a file names, one `{"type": ..., "id": ...}` object per
  line, at most 100,000 lines of at most 1,024 bytes, each with `--partial` and `--pending`, since the restored outbox
  is no new evidence; `restore_reconciled` is journalled only when every owner ended `complete` or `already_erased`.
  The file holds owner references, which the operator supplies from their own records and keeps as personal data.

## What Is Not Erased

- The references in an entry's columns: the actor, the subject, the principal and the tenant, as type and id pairs. A
  log that names no one is no evidence, so they are kept, and they remain personal data.
- Retained values, pseudonymised values, identifier hashes and hashed addresses: a hash is a pseudonym, linkable for as
  long as its key exists, and only `encrypt` puts a value under an owner's key.
- A note without an owner, which is stored in plaintext; an address stored in `full`, `truncate` or `hash` mode.
- The members of bulk, disclosure and export artifacts, encrypted under `app.key` because verification must decrypt
  them to check their digests: they are references, and an erasure leaves them as it leaves the columns.
- The key rows and the owner markers themselves, which keep the owner's type and id in plaintext columns so an erasure
  can find them and verification can fold them, and are never deleted; the journal's rows, which name the owner by a
  keyed fingerprint, and name the authority, its reason and any hold's scope.
- The records of reads, whose encrypted disclosure attachments keep the filters, the scope and the returned ids, and
  the read and erasure records sent to destinations.
- Every copy outside the live database: backups, replicas, exports, spill files, logs and destinations, which the
  operator's procedure reaches, or not.

## Stores And What They Hold

- **Entries** (`entries.table`): every record, its references, retained and hashed values, envelopes and integrity
  fields, because the log is evidence of who did what to whom. Personal data, sealed fields excepted while erased.
- **Artifacts** (`entries.artifacts_table`): a bulk, disclosure or export manifest's members, encrypted under
  `app.key`, because the record that describes them is verified against them. Personal data: references and, for a
  read, its filters and scope.
- **Outbox** (`delivery.outbox.table`): whole minimised records, encrypted under `app.key`, until a drain delivers
  them, because a record must survive its store being down. Personal data, as the spill is.
- **Receipts** (`delivery.deliveries_table`): an entry id, a destination, times and a failure's class, because a
  replay must not deliver twice. Linkable through the entry id.
- **Spill files**: whole minimised records in canonical JSON, unencrypted, because they must be readable when the store
  and its keys are not. Personal data, kept by the channel's own retention.
- **Checkpoints, members and integrity state** (`integrity.checkpoints_table`, `integrity.members_table`,
  `integrity.state_table`): seals, entry ids and HMACs, and the progress of the integrity commands, because the log's
  completeness is proved from them. Linkable through the entry ids.
- **Journal, holds and lock** (`lifecycle.journal_table`, `lifecycle.holds_table`, `lifecycle.lock_table`): each
  maintenance operation's authority, reason and external reference, hold scopes, which may name a person, owners'
  keyed fingerprints, and the lock's token of the running operation's id, because every destructive decision is
  accountable. Personal data while linkable, the token through the operation's journal rows.
- **Import batches** (`import.batches_table`): the importer's reference, the source, the file's digest and the
  conflicting source record ids, because an import is accountable. Personal data while linkable.
- **Subject keys, owner markers and key uses** (`privacy.subject_keys_table`, `privacy.owner_erasures_table`,
  `privacy.key_uses_table`): the owner's type and id, the tenant and category of each unit, wrapped keys, markers and
  the entries each key sealed, because erasure, reading and verification find an owner's keys and entries through
  them. Personal data: they name the owner, and erasure keeps them.
- **Exports**: canonical evidence files, envelopes as stored, wherever the operator writes them. Personal data, outside
  the package's reach.
- **Destinations and logs**: whatever each destination and log channel keeps of the records sent to it, and a
  report's ids and classes. Personal data in the destination's own store.

## Seams Left

- An external key service: `Contracts\KeyWrapper` is the seam, and the package ships only the local wrapper.
- An owner-specific projection for a subject access request, which the reveal grant is not.
- Erasure in the destinations' own stores, which `audit_log.subject_erased` announces and each destination applies.

## Implementation Anchors

- `src/Keys/KeyUnit.php`, `src/Integrity/SubjectKeyRow.php`: `unitOf()`, `wrapContext()`;
  `src/Integrity/SubjectKeySigner.php`, `src/Integrity/OwnerFingerprint.php`; `src/Integrity/Enums/KeyState.php`,
  `src/Integrity/Enums/MarkerTransition.php`.
- `src/Contracts/KeyWrapper.php`; `src/Keys/LocalKeyWrapper.php`, `src/Keys/WrappingRing.php`,
  `src/Keys/WrappingKey.php`, `src/Keys/KeySettings.php`, `src/Keys/UnknownWrappingKeyException.php`.
- `src/Keys/KeySession.php`, `src/Keys/OwnerLock.php`, `src/Keys/OwnerLockTimeoutException.php`,
  `src/Keys/OwnerMarker.php`, `src/Keys/OwnerMarkers.php`, `src/Keys/KeyStore.php`, `src/Keys/KeyCreator.php`;
  `src/Database/DedicatedSession.php`, `src/Database/KeyTables.php`.
- `src/Privacy/SubjectKeyEncrypter.php`, `src/Privacy/FieldCipher.php`, `src/Privacy/TypedPlaintext.php`,
  `src/Privacy/FieldContext.php`, `src/Privacy/SealingScope.php`, `src/Privacy/NoFieldEncrypter.php`,
  `src/Contracts/FieldEncrypter.php`.
- `src/Keys/KeyUses.php`, `src/Records/EnvelopeKeys.php`, `src/Keys/KeyUseRebuilder.php`,
  `src/Lifecycle/KeyUseRebuildResult.php`; `src/Stores/DatabaseAuditStore.php`: `store()`; `src/Lifecycle/ImportWriter.php`.
- `src/Access/AccessScope.php`: `revealingEncryptedFields()`; `src/Querying/EntryProjector.php`,
  `src/Privacy/EncryptedField.php`, `src/Contracts/FieldReader.php`, `src/Privacy/SubjectKeyFieldReader.php`,
  `src/Privacy/SealedFieldReader.php`, `src/Querying/FieldDisclosure.php`; `src/Querying/AuditTrail.php`:
  `holdingDataOf()`; `src/Privacy/KeyStoreUse.php`.
- `src/Lifecycle/Eraser.php`, `src/Lifecycle/ErasureBlocks.php`, `src/Lifecycle/ErasureBlock.php`,
  `src/Lifecycle/ErasureResult.php`, `src/Lifecycle/ErasureRefusedException.php`,
  `src/Lifecycle/Enums/ErasureRefusal.php`, `src/Lifecycle/Enums/ErasureStatus.php`.
- `src/Lifecycle/Reinstater.php`, `src/Lifecycle/ReinstateResult.php`,
  `src/Lifecycle/ReinstatementRefusedException.php`; `src/Lifecycle/Rewrapper.php`, `src/Lifecycle/RewrapResult.php`,
  `src/Lifecycle/Enums/RewrapStatus.php`.
- `src/Integrity/KeyStoreVerifier.php`, `src/Integrity/KeyUseCheck.php`, `src/Integrity/KeyStoreSummary.php`.

## Authoritative Tests

- `tests/Unit/Documentation/PrivacyDocumentationTest.php` `testThePrivacyNoteHasItsSectionsInOrder`,
  `testEachPrivacyStatementIsMade`, `testNoDocumentClaimsAStoreHoldsNoPersonalData`,
  `testNoDocumentClaimsErasurePreventsWhatCredentialsCanDo`
- `tests/Unit/Integrity/SubjectKeyRowTest.php` `testTheUnitDigestIsTheCanonicalUnit`,
  `testATenantlessUnitHasItsOwnDigest`, `testTheWrapContextBindsKeyUnitGenerationAndWrappingKey`,
  `testTheMutableFieldsAreNotSigned`
- `tests/Unit/Integrity/SubjectKeySignerTest.php` `testAnyChangedImmutableFieldFailsVerification`,
  `testTheKeyIsDerivedUnderItsOwnInfo`, `testTheGoldenHmacReproduces`
- `tests/Unit/Integrity/OwnerFingerprintTest.php` `testTheFingerprintIsKeyedAndStable`, `testItIsDerivedUnderItsOwnInfo`
- `tests/Unit/Keys/WrappingRingTest.php` `testTheDerivedIdIsADashedFingerprint`,
  `testARotatedAppKeyKeepsThePreviousForUnwrapping`, `testAnExplicitRingNeverFallsBackToTheAppKey`,
  `testTheDerivationIsSeparateFromTheIntegrityRing`, `testNothingIsCached`
- `tests/Unit/Keys/LocalKeyWrapperTest.php` `testTheGoldenVectorReproduces`, `testASubstitutedContextFailsToUnwrap`,
  `testAWrappedKeyUnderAnotherIdFails`, `testEachWrapUsesAFreshNonce`, `testNoMethodTakesANonce`
- `tests/Feature/Keys/KeySessionTest.php` `testInMemorySqliteUsesTheStorageConnection`,
  `testAFileDatabaseGetsADedicatedSessionOnTheWriter`, `testSqliteInsideAHostTransactionUsesTheStorageConnection`
- `tests/Integration/Keys/KeySessionEnginesTest.php` `testAKeySurvivesTheHostTransactionsRollback`
- `tests/Feature/Keys/KeyCreatorTest.php` `testAnErasedOwnerGetsNoKey`,
  `testAReinstatedOwnerGetsAGenerationAboveItsFloor`, `testACreationRaceIsSettledByTheUniqueIndexAndAReRead`,
  `testALiveKeyFoundAfterTheLockIsReturnedNotDoubled`, `testTheReadsAndTheInsertAreOneTransaction`,
  `testTheMarkerIsReadAfterTheLock`
- `tests/Integration/Keys/OwnerLockEnginesTest.php` `testASecondHolderWaitsForTheFirstsCommit`,
  `testAWaitPastTheLimitIsRefused`, `testOnSqliteTheWriteLockSerialisesTheHolders`
- `tests/Integration/Keys/KeyCreationRacesTest.php` `testAFirstKeyRacingAnErasureNeverSurvivesIt`
- `tests/Feature/Keys/KeyStoreTest.php` `testLiveKeysForEveryUnitInOneStatement`, `testByIdsReadsTheWriter`
- `tests/Unit/Privacy/FieldCipherTest.php` `testTheGoldenVectorReproduces`, `testANonceIsFreshEachTime`,
  `testNoMethodTakesANonce`, `testAnyChangedAuthenticatedPartFailsToOpen`, `testTheFieldKeyIsDerivedPerEntry`,
  `testAMalformedCiphertextIsRefused`
- `tests/Unit/Privacy/TypedPlaintextTest.php` `testAStringTrueIsNotTheBooleanTrue`, `testAStringIsCutSoItsEncodingFits`,
  `testAnyOtherValueOverTheLimitIsNull`
- `tests/Feature/Privacy/SubjectKeyEncrypterTest.php` `testOneLookupServesEveryOwnerOfTheRecord`,
  `testAnErasedOwnersFieldIsDropped`, `testAnotherEntryStartsAfresh`, `testNoWrappingSecretIsHeld`
- `tests/Feature/Privacy/KeyCachingTest.php` `testAWorkerWritingAfterAnErasureNeverEncryptsUnderTheErasedKey`,
  `testAPageReadAfterAnErasureShowsErased`, `testOctaneRequestsShareNoKey`
- `tests/Feature/Privacy/EncryptionProofsTest.php` `testNoPlaintextIsStoredForAnAbsentOrErasedOwner`,
  `testTheOutboxHoldsOnlyTheEnvelope`
- `tests/Feature/Privacy/CiphertextRelocationTest.php` `testAnEnvelopeCopiedToAnotherEntryIsUnreadable`,
  `testAnEnvelopeMovedToAnotherPathIsUnreadable`, `testAnEnvelopeMovedBetweenListPositionsIsUnreadable`,
  `testARowEditedToHoldACopiedEnvelopeFailsItsHmac`
- `tests/Unit/Records/EnvelopeKeysTest.php` `testItFindsExactlyWhatTheProjectorReadsAsAnEnvelope`
- `tests/Feature/Keys/KeyUsesTest.php` `testANonUuidKeyHasNoRow`
- `tests/Feature/Keys/KeyUsesPathsTest.php` `testTheOutboxDrainWritesKeyUses`, `testSpillReplayWritesKeyUses`,
  `testAnImportWritesKeyUses`
- `tests/Integration/Stores/DatabaseAuditStoreTest.php` `testAnEncryptedRecordWritesItsKeyUsesWithIt`,
  `testAFailedKeyUseRollsTheEntryBack`
- `tests/Performance/EncryptedWriteBudgetTest.php` `testAnUnencryptedRecordKeepsItsSingleInsert`,
  `testInsideAHostTransactionTheKeyUsesShareTheSavepoint`
- `tests/Feature/Keys/KeyUseRebuilderTest.php` `testOnlyRowsWhoseHmacVerifiesAreTrusted`, `testNothingIsEverRemoved`
- `tests/Integration/Querying/HoldingDataOfEnginesTest.php` `testAnEntryHoldingTwoOwnersIsFoundForEach`
- `tests/Feature/Querying/AuditTrailTest.php` `testACustomEncrypterThrowsNamingTheBinding`,
  `testAnErasedOwnersEntriesAreStillFound`
- `tests/Unit/Access/AccessScopeTest.php` `testRevealingIsOffOnEveryStartingScope`, `testADeniedScopeNeverReveals`,
  `testTheGrantIsInTheNormalisedFormAndFingerprint`
- `tests/Feature/Querying/EntryProjectorTest.php` `testANonRevealingProjectionNeverCallsTheReader`,
  `testARowThatFailsItsHmacShowsEveryEnvelopeUnreadable`, `testTheFieldsOfAPageAreReadInOneCall`
- `tests/Unit/Privacy/EncryptedFieldTest.php` `testOnlyTheFactoryBuildsOne`
- `tests/Feature/Privacy/SubjectKeyFieldReaderTest.php` `testErasedNeedsAVerifiedErasureRowListingTheKey`,
  `testANullKeyWithoutAnErasureRowIsUnreadable`, `testAReplicaIsNeverReadForAKey`, `testNothingIsKeptBetweenPages`
- `tests/Unit/Querying/AccessEvidenceTest.php` `testAPageRecordsItsRevealGrantAndFieldCounts`
- `tests/Feature/Querying/RevealedReadingTest.php` `testEachMarkerThroughARevealingScope`,
  `testANonRevealingScopeNeverCallsTheReader`
- `tests/Integration/Privacy/ConcurrentRevealTest.php` `testAReadAfterTheErasureCommitsNeverReveals`
- `tests/Feature/Lifecycle/EraserTest.php` `testAHeldUnitRefusesTheWholeErasure`,
  `testAPreservedUnitRefusesTheWholeErasure`, `testPartialDestroysTheUnblockedUnitsAndReportsTheRest`,
  `testAHoldOnOneCategoryLeavesAnotherUnitErasable`, `testAnOutboxRowOlderThanTheErasureRefusesIt`,
  `testPendingAcceptsItAndTheDeliveredRecordIsErased`, `testAHoldProtectsARecordOnlyOnceStored`,
  `testTheJournalRowListsEveryDestroyedKeyWithItsBeforeAndAfter`, `testTheKeysAreTombstonedWithTheErasureRowsId`,
  `testTheEntriesAffectedAreDistinctEntries`, `testAnAlreadyErasedOwnerIsANoOp`, `testACustomEncrypterIsRefused`,
  `testAKeyThatFailsItsSignatureRefusesTheErasure`, `testHmacsStillVerifyAfterTheErasure`
- `tests/Feature/Lifecycle/ErasureBlocksTest.php` `testAnEntryFailingItsHmacBlocksItsKey`,
  `testPreservationIsDecidedPerEntryFromItsOccurrence`, `testAPrunedEntrysKeyUseBlocksNothing`
- `tests/Feature/Lifecycle/ReinstaterTest.php` `testAMarkerNotInTheChainRefuses`, `testTheNextKeyIsAboveTheFloor`,
  `testAnErasedGenerationNeverReopens`
- `tests/Feature/Lifecycle/RewrapperTest.php` `testRotateSupersedesLiveKeysAndTheNextWriteOpensAGeneration`,
  `testAKeyThatFailsToUnwrapIsSkippedAndReported`
- `tests/Feature/Integrity/KeyStoreVerifierTest.php` `testAKeyNulledWithoutAnErasureIsUnjournalled`,
  `testALiveKeyOfAnErasedOwnerIsRestored`, `testAKeptKeyOfAPartialErasureIsClean`,
  `testAWrappedKeyMovedFromAnotherRowIsSubstituted`
- `tests/Feature/Integrity/KeyStoreTamperingTest.php` `testADeletedKeyUseIsFoundByVerify`,
  `testAnUnjournalledDestructionIsFoundAndReadsUnreadable`, `testARestoredKeyIsFoundByVerify`
- `tests/Unit/Privacy/KeyStoreUseTest.php` `testThePackagesEncryptersUseTheKeyStore`, `testACustomEncrypterDoesNot`

## Change Triggers

Update this note when any of the following change:

- what a key unit is, a key's states, its row, its signature or what the wrap binds
- the wrapping ring, its derivation, its ids, or the `Contracts\KeyWrapper` contract
- where or how a key is created, the owner's lock, the markers or the generation floor
- the field key, the envelope, its additional data, the path or the typed plaintext
- what writes a key use, what verification checks of them, or what a rebuild may do
- the reveal grant, what a reader is given, or what a read's record counts
- what an erasure checks, refuses, journals, tombstones or records, or what a reinstatement or a rewrap does
- what a restore brings back, what finds it, or what reconciles it
- what an erasure does not reach
- what a store holds, or why
