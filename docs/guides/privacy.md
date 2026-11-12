# Privacy

An audit log is personal data about everyone it names. The package seals the fields a definition marks for encryption
under a key of their owner, lets a viewer read them only under an explicit grant, and erases an owner by destroying that
owner's keys, so every field ever sealed for the owner, wherever it is stored, sent or replayed, reads `erased` while
every entry, seal and journal row still verifies. This guide covers the defaults and what each trades, the keys, erasure
and its two outcomes, recall, reinstatement, rotation, restores, what an erasure does not reach, what each store holds,
custom encrypters, SQLite's key session and the commands. How each part works, with every value it settles, is in [the
privacy note](../design/privacy.md); reading sealed fields and the subject access procedure are in [the reading
guide](reading.md); holds and preservation are in [the retention guide](retention.md).

Database credentials can still destroy keys, key uses and markers; the package's cryptographic evidence makes
unauthorised destruction, substitution or restoration detectable, never impossible. An erasure revokes an owner's
fields in the live store when it commits; whoever holds the database credentials, or a backup, can still delete or
bring back rows and keys, and `audit-log:verify` and `audit-log:check` report what they did.

## Defaults and their trade-offs

| Default                               | What it does                                                                     | What it trades                                                                             |
|---------------------------------------|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `Privacy\SubjectKeyEncrypter` bound   | Seals every field a definition encrypts, an owned note and an `encrypt` address  | A key row per owner, tenant and category, and key uses beside every sealed entry           |
| `Privacy\SubjectKeyFieldReader` bound | Opens a page's sealed fields for a viewer whose scope reveals them               | One key read per page on the storage writer                                                |
| `Keys\LocalKeyWrapper` bound          | Wraps every data key under `app.key`'s derived key, unless `privacy.keys` is set | A backup of the database and the configuration together restores what an erasure destroyed |
| No scope reveals encrypted fields     | Shows every sealed field as `[ENCRYPTED]`                                        | Reading one takes a policy that grants `revealingEncryptedFields()`                        |
| `redaction.ip` is `full`              | Keeps the client address as given                                                | An address is personal data, kept in plaintext; `encrypt` seals it under the actor         |
| `redaction.identifiers` is `hash`     | Keeps a keyed hash of a sign-in identifier                                       | A hash is a pseudonym, linkable while its key exists, and no erasure reaches it            |
| No retention settings                 | Keeps every entry forever                                                        | Keeping entries forever is not a compliance default; set a retention that fits the data    |

- Fields a definition encrypts are sealed by default. `encrypt('card', KeyOwner::ACTOR)` names whose key seals a field,
  and nothing else needs binding. Bind `Privacy\NoFieldEncrypter` as `Contracts\FieldEncrypter` to never encrypt: every
  value a definition marks for encryption is then dropped and diagnosed, never stored in plaintext, and erasure keeps
  working on the keys already made.
- A value is sealed as typed plaintext, the canonical JSON of the value, so the string `"true"` and the boolean `true`
  differ, at most 1,024 bytes after encoding: a longer string is cut on a character boundary, and any other value over
  the limit is dropped and diagnosed.
- A field whose owner is absent from the record, or erased, is dropped and counted as an omission with no reason, so a
  later record about an erased owner never says the owner was erased.
- The reveal grant is the access policy's to give, per viewer and purpose. The grant reveals every encrypted field of
  every entry the scope sees, whoever owns it, and is not an owner-specific projection: `holdingDataOf()` selects the
  entries holding an owner's fragments, and the other owners' fragments those entries hold are revealed too, so review
  them before anything is disclosed. A read under the grant records `reveal` and how many fragments it showed
  `encrypted`, `erased`, `revealed` and `unreadable`, never a value.

## Keys

- A key unit is the owner, the record's tenant and the definition's category, so a hold or a preservation on one of an
  owner's categories keeps that unit's key and lets the owner's other units go, and an id reused by two tenants never
  shares a key. Each unit has generations, one key row each, `live`, `superseded` or `erased`; an erased generation
  never reopens.
- Every data key is random and stored only wrapped, under the wrapping key `Contracts\KeyWrapper` names as current,
  bound to its row, unit, generation and wrapping key id, so a wrapped key moved or substituted does not unwrap.
- The wrapping ring is `privacy.keys`, key ids to secrets of at least 32 bytes, with `privacy.current` naming the key
  that wraps; both are set or neither, and an explicit ring never wraps under `app.key`. Without them, the wrapping
  keys are derived from `app.key` and each of `app.previous_keys`, under their own info string. The derivation gives
  domain separation, not independence from `app.key`: anyone holding `app.key` holds the derived wrapping keys, and a
  rotated `app.key` must stay in `app.previous_keys` for as long as a key it wrapped is not rewrapped. Use
  `privacy.keys` before going live.
- To move from the derived keys to `privacy.keys`, set `privacy.keys` and `privacy.current`, keep `app.key` and
  `app.previous_keys` as they are, and run `audit-log:rewrap`. The keys derived from `app.key` and `app.previous_keys`
  stay in an explicit ring to unwrap only, so the keys wrapped before the move still open and the rewrap moves them
  onto `privacy.current`; once a run ends `complete`, no key depends on `app.key` any longer. `audit-log:check` reports
  a live or superseded key wrapped under a key the ring does not hold.
- `audit-log:rewrap`, or `AuditLog::lifecycle()->rewrap($authority)`, wraps every live or superseded key again under the
  current wrapping key, in batches of `privacy.rewrap_batch` (500 by default, from 100 to 10000), each journalled; run
  it after adding a wrapping key and pointing `privacy.current` at it, and drop the old key only once a run ends
  `complete`. A key it cannot authenticate or unwrap is skipped, named, and left for verification to report.
- `audit-log:rewrap --rotate` also supersedes every live key, so the next write of each unit opens its next generation.
  Rotation is not rewrap: a superseded key still opens what it sealed.
- The `Contracts\KeyWrapper` seam lets a key service outside the application wrap the data keys. Under `LocalKeyWrapper`
  the wrapping keys live in the application's configuration, so a backup of the database and of the configuration
  together still holds the keys an erasure destroyed; a wrapper whose wrapping keys are destroyed outside the database's
  backups is what lets an erasure reach a backup.
- Keep the wrapping keys and the integrity ring out of the database and its backups. No key is held in memory beyond one
  operation: one record's write, or one page's read.

## Erasure

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Records\Reference;

$result = AuditLog::lifecycle()->erase(
    $user,
    new Authority(Reference::to($operator), 'gdpr.article_17', 'dpo:case-2026-118'),
);

$result->status;          // complete, partial or already_erased
$result->entriesAffected; // the entries the destroyed keys sealed
```

- An erasure is all or nothing. Under the lifecycle lock it verifies the journal and replays its holds, reads the
  owner's keys and verifies each, reads every entry each key sealed through its key uses and verifies each entry's HMAC,
  and refuses the whole erasure, writing nothing, when any key is blocked: `held:<hold id>` by an active hold whose
  scope matches an entry, `preserved:<category>` by an entry still inside its category's preservation, or `unverified`
  by an entry that fails its HMAC. `--partial`, or `partial: true`, destroys the keys nothing blocks and keeps the rest,
  reporting each kept key's reasons in the result, the journal row and the record.
- A hold is not a blanket exemption under Article 17 for every fragment of a person. It keeps what its scope matches,
  for the basis it names; units are what let the owner's unrelated data go, so scope a hold to the categories its basis
  needs. The package records the basis it is given and never decides legal necessity.
- An erasure refuses while the outbox holds records created before it started, failed ones included
  (`pending_delivery`), since every field of the owner they hold is erased with the key. `--pending` accepts them: they
  are delivered later, their fields `erased`. A hold protects a record only once it is stored, so a held record still in
  the outbox is erased with its key whatever the hold says. Spilled records awaiting replay are pending evidence the
  erasure cannot see: replay the spill before erasing, or accept that what it holds is erased too.
- An erasure is refused `unsupported_encrypter` while another field encrypter is bound, `key_unverifiable` when a key of
  the owner fails its signature, and `too_many_keys` beyond 10,000 keys. A broken journal refuses it too.
- An erasure that goes ahead journals the destroyed keys, each with its state and digests before and after, tombstones
  them and marks the owner erased, so no key is created for the owner again until a reinstatement. Its record,
  `audit_log.subject_erased`, names the owner only by a keyed fingerprint, and is sent to the destinations like any
  record, so each can apply the erasure to what it holds. The fingerprint is personal data while it can be linked.
- An erasure has two outcomes, named apart. Revoked in the live store is what the package does: from the commit no read
  reveals the owner's fields. Erasure complete is the operator's procedure across the estate, and an erasure is complete
  only once each of these no longer holds the owner's keys or plaintext:
  - backups of the database, with their WAL or binlogs, expiring past the erasure, or restored only with
    `audit-log:erase --reapply`
  - replicas, which follow the primary once they catch up
  - exports, which keep envelopes as stored and the keys that open them only as long as the database does
  - logs and error trackers, which the package writes ids and classes to, never values
  - destination stores, such as a SIEM, which receive `audit_log.subject_erased` and apply it themselves
  - pending deliveries, accepted with `--pending` and erased by construction once they land

## Recall

A decryption already returned cannot be recalled. An erasure's commit is the point after which no read reveals the
owner's fields; a page read before it showed what it showed, and a viewer who copied a value keeps it. The read's record
says which pages revealed fields and how many, so an erasure can be followed by the reads that preceded it.

## Reinstatement

`AuditLog::lifecycle()->reinstate($owner, $authority)`, or `audit-log:reinstate`, lets keys be created for an erased
owner again, above the floor of the erasure: it creates no key and makes no erased field readable, and the owner's next
write opens a new generation. An owner who is not erased is refused `not_erased`. A reinstatement is journalled and
recorded as `audit_log.keys_reinstated`.

## Rotation and kept units

A partial erasure marks the owner erased while its kept keys go on sealing what their units already seal, since their
obligation stands, and no other unit or generation of the owner is created until a reinstatement.
`audit-log:rewrap --rotate` supersedes a kept key like any live one: a kept key's unit then seals nothing for that owner
until a reinstatement, and new fields of it are dropped as an erased owner's are. Release the hold and erase again to
destroy a kept key once its obligation ends.

## Restores

A restored key decrypts until the erasure is re-applied. A database restored from before an erasure brings the erased
keys back, wrapped, and under `LocalKeyWrapper` the restored configuration still unwraps them.

- `audit-log:verify` reports a key that is live while its owner's latest verified transition is an erasure that did not
  keep it as `key_restored`, and a key destroyed without a journalled erasure as `key_destroyed_unjournalled`.
- `audit-log:check` reports both, and a database restored behind its anchor, as a problem until the erasures are
  re-applied. Without an anchor that reports its head, a full restore cannot be found: the journal and the seals are
  restored with the database, and only the anchor holds a later head.
- `audit-log:erase --reapply=<file>`, or `AuditLog::lifecycle()->reapplyErasures($path, $authority)`, erases again every
  owner the file names, one JSON object per line, `{"type": "App\\Models\\User", "id": "42"}`, at most 100,000 lines
  that are not blank, each of at most 1,024 bytes. Each owner is erased in part and accepting pending deliveries, since
  the restored outbox is no new evidence, and the restore is journalled reconciled, with the anchor's head, only when
  every owner ended `complete` or `already_erased` and every line named an owner. The file holds owner references, kept
  from the operator's own records of erasures, and is personal data: keep it where the backups are not.

## What is not erased

- The references in an entry's columns, the actor, subject, principal and tenant: a log that names no one is no
  evidence. They remain personal data.
- Retained, pseudonymised and hashed values, a hashed identifier and an address kept `full`, `truncate` or `hash`; a
  note without an owner.
- Manifest members under `app.key`: the members of bulk, disclosure and export artifacts are encrypted under `app.key`,
  because verification decrypts them, and an erasure leaves them as it leaves the columns.
- The journal's fingerprints of erased owners, its authorities, reasons and hold scopes, and the key rows and owner
  markers, which keep the owner's type and id so erasure and verification can find them.
- The read evidence's filters naming an owner: a read's record and its disclosure manifest keep the filters, the scope
  and the ids it returned.
- Every copy outside the live database, which the estate procedure above reaches, or not.

## Stores and what they hold

| Store                                                        | What it holds                                                                   | Why                                           |
|--------------------------------------------------------------|---------------------------------------------------------------------------------|-----------------------------------------------|
| Entries (`entries.table`)                                    | Records, references, retained and hashed values, envelopes, integrity fields    | The log is evidence of who did what to whom   |
| Artifacts (`entries.artifacts_table`)                        | Manifest members under `app.key`: references, a read's filters and scope        | A record is verified against its members      |
| Outbox (`delivery.outbox.table`)                             | Whole minimised records under `app.key` until a drain delivers them             | A record survives its store being down        |
| Receipts (`delivery.deliveries_table`)                       | Entry ids, destinations, times and failure classes                              | A replay never delivers twice                 |
| Spill files                                                  | Whole minimised records, unencrypted                                            | They are read when the store and keys are not |
| Seals and integrity state (`integrity.*`)                    | Seals, entry ids, HMACs and progress                                            | Completeness is proved from them              |
| Journal, holds and lock (`lifecycle.*`)                      | Authorities, reasons, references, hold scopes, owners' fingerprints, the token  | Every destructive decision is accountable     |
| Import batches (`import.batches_table`)                      | The importer, the source, the file's digest, conflicting source record ids      | An import is accountable                      |
| Subject keys, owner markers and key uses (`privacy.*_table`) | Owners' types and ids, units, wrapped keys, markers and the entries each sealed | Erasure, reading and verification find them   |
| Exports, destinations and logs                               | Whatever each keeps of the records sent to it, envelopes as stored              | Outside the package's reach                   |

Each store holds personal data while what it keeps can be linked to a person: a keyed fingerprint, a reference, an
authority id, a hold scope and a read filter all can. The privacy note lists each store and what it holds in full.

## Custom encrypters

The package's key store is in use while the bound field encrypter is `Privacy\SubjectKeyEncrypter` or
`Privacy\NoFieldEncrypter`, by exact class: a subclass or a decorator is another encrypter. With any other encrypter, an
erasure refuses `unsupported_encrypter`, `holdingDataOf()` throws a `\LogicException` naming the bound class, the
verification's key store section reports itself skipped and `audit-log:check` notes it: the keys it made are where the
package cannot see them. An envelope whose `k` is a lower-case UUID still gets key uses, whatever made it, so after a
move from such an encrypter to the package's key store its UUID references are reported `key_missing` by verify, having
no key row; keep the old encrypter's keys, or expect those findings for the entries it sealed.

## SQLite and the key session

A key is created on a session of its own, a second connection to the storage connection's writer, so it commits on its
own and survives a host transaction that rolls back while a spill or the outbox already holds ciphertext under it. Where
a second connection cannot see or write what the storage connection does, in-memory SQLite, the testing manager's base
transaction, and SQLite whenever the storage connection is inside a transaction, the storage connection itself is the
session: a key created inside a host transaction on SQLite rolls back with it, and the fields sealed under it then open
under no key, reading `unreadable`. Use MySQL or PostgreSQL where that matters.

## Commands

Each command trusts the shell, as the other maintenance commands do: `--by-type` and `--by-id` assert the operator and
prove nothing, `--reason` is a reason code and `--reference` the ticket or case. Each prints counts, ids, fingerprints
and reasons, never an owner, names a failure by its class and never its message, and exits 0 when it is done, 1 when it
is refused or fails, and 2 for an argument or option it refuses, before anything runs.

| Command                           | Options                                                                                  | What it does                                                                                  |
|-----------------------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `audit-log:erase [type] [id]`     | `--by-type`, `--by-id`, `--reason`, `--reference`, `--partial`, `--pending`, `--reapply` | Erases an owner, or with `--reapply` every owner a file names after a restore                 |
| `audit-log:reinstate <type> <id>` | `--by-type`, `--by-id`, `--reason`, `--reference`                                        | Reinstates an erased owner, so keys may be created again above its floor                      |
| `audit-log:rewrap`                | `--by-type`, `--by-id`, `--reason`, `--reference`, `--rotate`, `--dry-run`               | Rewraps every key onto the current wrapping key, and with `--rotate` supersedes the live ones |
| `audit-log:keys`                  | `--rebuild-uses`, `--dry-run`                                                            | Adds the key uses missing from the entries whose HMAC verifies, and never removes one         |

- `audit-log:erase` exits 0 for `complete`, `partial` and `already_erased`; a `--reapply` exits 0 once the restore is
  reconciled and 1 when it is not. `--reapply` takes no owner, `--partial` or `--pending`.
- `audit-log:rewrap --dry-run` reads and unwraps every key it would rewrap and writes nothing; a run that skipped a key
  ends `partial` and still exits 0.
- `audit-log:keys --rebuild-uses`, or `AuditLog::lifecycle()->rebuildKeyUses()`, needs no authority and journals
  nothing: key uses are derived from the signed entries, and `audit-log:verify` reports one still missing.
