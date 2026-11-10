# Reading

The trail is read through one immutable query, for one viewer, under the scope an access policy the application binds
gives that viewer. Every page, count, export and verification is itself recorded before anything it found is returned,
and nothing is read until the application has bound a policy: the package's own denies every viewer.

## Reading the trail

`AuditLog::trail()` gives a fresh trail of every entry; resolving `Querying\AuditTrail` from the container gives the
same. Each filter returns a new trail and leaves the one it was called on as it was, so a trail kept in a property and
shared between requests leaks no filter:

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

$page = AuditLog::trail()
    ->visibleTo($user)
    ->forSubject($invoice)
    ->forEventsUnder('invoice.')
    ->withOutcome(Outcome::FAILURE, Outcome::DENIED)
    ->between(now()->subDays(30), null)
    ->cursorPaginate();
```

| Filter                                                        | Keeps the entries                                                                   |
|---------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `forActor()`, `forSubject()`, `forPrincipal()`, `forTenant()` | whose actor, subject, principal or tenant is the model or the `Records\Reference`   |
| `forEvent(...$codes)`                                         | with one of these exact codes, a string or a backed enum case, at most 50           |
| `forEventsUnder($prefix)`                                     | whose code starts with the dotted prefix, such as `invoice.`, ending in a dot       |
| `inCategory(...$categories)`                                  | in one of these categories, at most 50                                              |
| `withOutcome(...$outcomes)`                                   | with one of these outcomes                                                          |
| `between($from, $to)`                                         | that occurred from `$from`, inclusive, before `$to`, exclusive; `null` for no limit |
| `correlatedWith($correlationId)`                              | carrying the namespaced correlation id                                              |
| `holdingDataOf($owner)`                                       | holding a fragment sealed under one of the owner's keys, whoever they are about     |

- A model is referred to exactly as capture refers to it, by its morph class and key, so a trail finds what was
  recorded about it. Nothing joins the application's tables, so a deleted user's history reads as it did.
- Each dimension replaces itself, and the dimensions are combined: `forEvent()` and `forEventsUnder()` are one
  dimension, so either replaces the other, and `between(null, null)` clears the window. A window whose start is not
  before its end is refused.
- A filter is validated as it is given, and a malformed one is refused with an `\InvalidArgumentException` naming the
  filter, never its value, before anything is read. A code under `audit_log.` can be filtered on, though no application
  can record one.
- `holdingDataOf()` keeps the entries holding a fragment sealed under one of the owner's keys, through the key uses the
  store writes with each entry, whether or not the entry names the owner. It selects entries and reveals nothing: what
  their fragments show is the scope's to grant. It reads the package's key store, so while a field encrypter other than
  the package's is bound it is refused with a `\LogicException` naming that encrypter, before anything is read.
- The trail reads the storage connection, and a replica when the connection configures one, never the writer pinned
  for recording. So the trail is not read-your-writes: a record just written may not be on the page read next.

## Viewers and the access policy

Every terminal call, `cursorPaginate()`, `count()`, `export()` and `verifyExport()`, reads for the viewer
`visibleTo()` names. A call without one is a `\LogicException` before anything is queried, and is not recorded, since it
is a mistake in the code and not a read.

The viewer is a model or another authenticatable user, referenced as capture references a user, or a
`Records\Reference`. The application authenticates the viewer: a `Reference` viewer is an assertion, not
authentication. A viewer that cannot be referenced, such as a model without a key, is refused with an
`\InvalidArgumentException`, never read as anonymous.

What a viewer may see is the access policy's to answer. Bind one in a service provider's `register()`:

```php
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;

$this->app->singleton(AuditAccessPolicy::class, OrganisationAuditPolicy::class);
```

```php
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

final class OrganisationAuditPolicy implements AuditAccessPolicy
{
    public function scope(Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        if (!$viewer instanceof User || !$viewer->isAuditor()) {
            return AccessScope::none();
        }

        $scope = AccessScope::tenants(Reference::to($viewer->organisation));

        return $purpose === ReadPurpose::EXPORT ? $scope->exceptCategories('security') : $scope;
    }
}
```

- The policy is asked on every terminal call, with the viewer exactly as `visibleTo()` was given it and the purpose:
  `read` for a page, `count` for a count, `export` for an export and `verify` for the verification of one. So a viewer
  may page through entries it may never export.
- The package binds `Access\DenyAllPolicy` until the application binds its own, so by default every read is empty and
  recorded as denied.
- The policy is told who is reading and why, never how they signed in or how recently. A requirement on the
  authentication itself, such as a fresh multi-factor check or a confirmed password, belongs on the route or action
  that reads the trail, enforced before `visibleTo()` is called. A policy that cannot tell whether such a requirement
  is met treats the permission as not held.
- A policy keeps no state between calls and never reads the entries table. What it throws is recorded as a failed read
  with the reason `policy_failed`, and reaches the caller unchanged.
- A denied viewer sees what an empty trail shows: an empty page, `0`, an empty export, or a verification that cannot
  find the export's entry. The denial is recorded with the reason `no_scope`. There is no way to ask whether a viewer
  may read without reading, so a portal that wants to hide a link reads its own permissions, not the trail's.

## Scopes

An `Access\AccessScope` is what the policy answers with. It starts from one of three, and is then narrowed:

- `AccessScope::none()` sees nothing, and absorbs every operation: whatever is done to it, it stays denied.
- `AccessScope::all()` sees every entry, of every tenant and of none.
- `AccessScope::tenants(...$tenants)` sees the entries of exactly these tenants, each matched as its type and id
  together, at most 100. `withTenantless()` adds the entries whose tenant type and tenant id are both `null`.

Narrow a scope only through its instance methods, each of which only ever intersects with what the scope already holds,
so repeating one never widens it:

```php
$scope = AccessScope::tenants(Reference::to($organisation))
    ->withTenantless()
    ->onlyCategories('finance', 'security')
    ->exceptCategories('security')
    ->onlyAbout(Reference::to($user));
```

- `onlyCategories()` keeps these categories of what the scope sees, and `exceptCategories()` removes them, at most 50.
- `onlyAbout()` keeps the entries whose actor or subject is one of these references, at most 100. `onlyAbout()` selects
  rows by actor or subject only; it is not a complete disclosure policy. An entry about one person can name another,
  and an entry whose principal or tenant is the person is not selected.
- A list left empty, given empty or emptied by an intersection, denies; it never means unrestricted.
- PHP lets a static factory be reached through an instance. A static factory reached through an instance starts a fresh
  scope: `$scope->tenants($other)` or `$scope->all()` discards every restriction `$scope` held.
- The scope is applied to every statement before the caller's filters, which can only narrow it. A filter outside the
  scope, such as `forTenant()` with a tenant the viewer does not see, gives the same empty result as a tenant that does
  not exist, and a scope or filters that can match nothing run no statement at all.

## Pages and cursors

`cursorPaginate($perPage = null, $cursor = null)` gives a `Querying\TrailPage` of at most `$perPage` entries, newest
first by when they occurred, then by id. Its `entries` are `Querying\TrailEntry` values, `hasMore()` says whether
another page follows, and `nextCursor` opens it:

```php
$trail = AuditLog::trail()->visibleTo($user)->forActor($user);

$page = $trail->cursorPaginate(25);

if ($page->hasMore()) {
    $next = $trail->cursorPaginate(25, $page->nextCursor);
}
```

- `$perPage` is from 1 to `read.max_per_page`, 100 by default, and one outside that range is an
  `\InvalidArgumentException` before anything is queried, and is not recorded. Without one, a page holds 50 entries, or
  `read.max_per_page` when that is fewer, so the call with no arguments works under any valid setting. A page and the
  cursor it gives are bound to the size it was read at, so ask for the next page with the same size, or with none
  again.
- A page never says how many entries there are in all; `count()` is its own read.
- A cursor is opaque and signed. It opens only the next page of the read it came from: the same viewer, purpose, scope,
  filters and page size, on the same log. Any other use, or a cursor tampered with or signed under a key the ring no
  longer holds, is refused with `Querying\InvalidCursorException`, whose message is the same whatever the cause, and
  the refusal is recorded as denied with the reason `cursor_rejected`.
- A cursor never expires, but it is bound to the scope the policy answered when it was issued, and the scope is asked
  again on every page. Once that scope changes in any way, narrowed, widened or revoked, the cursor is refused with
  `Querying\InvalidCursorException` and the read is recorded as `cursor_rejected`, so a cursor never reads under a
  scope it was not issued for; the portal starts again from the first page. A viewer who is now denied altogether is
  answered as any denied viewer is, with an empty page and a denial recorded as `no_scope`, before the cursor is
  looked at, so the answer does not say whether the trail is empty or the access was revoked. A cursor still opens
  after a key rotation while its key stays in the ring, and pruning the entry it points past never invalidates it.
- Walking the pages repeats no entry, and skips no entry that was present and visible when the first page was read,
  provided a later page does not read an older replica. An entry is ordered by when it occurred, and entries arrive late
  from queues, the outbox and imports, so a row inserted later into an interval already walked may be missed.

## Counting

`count()` is how many entries the viewer may see under the filters, read under the purpose `count` and recorded as its
own read, with nothing of the entries disclosed. It counts exactly what the pages would show, and is `0` for a denied
viewer.

```php
$failures = AuditLog::trail()->visibleTo($user)->withOutcome(Outcome::FAILURE)->count();
```

## Describing entries

A `Querying\TrailEntry` is an entry as a viewer is shown it, safe to hand on: its references, times, code, outcome and
versions as typed values, a reason its record concealed already `null`, and its context and properties as display
arrays. `toArray()` gives it with snake-case keys, references as `type` and `id` and times in UTC to the microsecond. An
artifact the entry carries, a bulk operation's members for instance, is shown by its `manifest` descriptor alone, its
kind, count and digest, and its members are never loaded. The stored row is the evidence; an entry is a projection of
it.

`Querying\Describer` gives an entry's title for a person:

```php
use SineMacula\Laravel\AuditLog\Querying\Describer;

$description = app(Describer::class)->describe($entry, 'fr');

$description->title;   // the code's title in French, else in the fallback locale, else the code
$description->reason;  // the reason, or null when there is none or it was concealed
```

- Titles come from a flat file keyed by the whole code, `lang/en/codes.php`, under the `audit-log` namespace, so
  `invoice.approved` and `invoice.approved.twice` never collide. The package ships a title for every code it records.
- An application adds its own codes' titles, and overrides the package's, in `lang/vendor/audit-log/{locale}/codes.php`;
  `php artisan vendor:publish --tag=audit-log-lang` copies the shipped file there.
- Only a non-empty string is a title, and no stored value is ever replaced into one, so nothing an entry holds reaches a
  translated sentence. A missing title is never an error: the code is the title.

## Encrypted fields

A field sealed under its owner's key, an owned note, or an IP address stored under the `encrypt` mode is never shown as
its ciphertext. Wherever it sits, in the properties, the context or the network details, it is shown as its value only
to a viewer whose scope reveals encrypted fields, and otherwise as the marker of its `Privacy\Enums\FieldState`:

| State        | Marker         | When                                                                                                                                                                                                       |
|--------------|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `encrypted`  | `[ENCRYPTED]`  | the scope does not reveal encrypted fields, or the bound reader opens none                                                                                                                                 |
| `erased`     | `[ERASED]`     | sealed under a key a journalled erasure destroyed; the live store cannot read it, and a restored backup reads it until the erasure is re-applied (see the privacy guide's [Restores](privacy.md#restores)) |
| `unreadable` | `[UNREADABLE]` | its row or its envelope fails authentication or is malformed, or the reader failed                                                                                                                         |

Who may read a sealed field is the access policy's to decide, per viewer and purpose. A scope reveals encrypted fields
only once the policy grants it `revealingEncryptedFields()`, for instance to the auditors who read pages:

```php
$scope = AccessScope::tenants(Reference::to($viewer->organisation));

return $purpose === ReadPurpose::READ ? $scope->revealingEncryptedFields() : $scope;
```

- The grant is off on every starting scope and kept by every narrowing. A denied scope stays denied and reveals nothing.
  Without the grant no reader is asked, and every sealed field shows `[ENCRYPTED]`.
- The grant is part of the scope's normalised form and fingerprint, so a cursor issued without it is refused once the
  scope reveals, and the other way round, as for any change of scope.
- The grant reveals every encrypted field of every entry the scope sees, whoever owns it: it is not an owner-specific
  projection. An entry holding one person's fragment can hold another person's, revealed beside it.
- Only a page reveals. A count and an export never decrypt: an export keeps every envelope as stored, the canonical
  evidence, whatever the scope grants.
- A page read under the grant records `reveal` and `fields`, how many fragments it showed `encrypted`, `erased`,
  `revealed` and `unreadable`, never a value.
- A decryption already returned cannot be recalled. An erasure stops every read after its commit, never one that has
  already shown a value.

Under the grant, each row's HMAC is verified before any field of it is read. A row that fails, or that is signed under a
key the ring does not hold, shows every sealed field it holds as `[UNREADABLE]`, and none of them reaches the reader, so
a row edited in the database never has an envelope opened. The fields of the authenticated rows of a page are then read
together, in one call.

The package binds `Privacy\SubjectKeyFieldReader`, which reads the keys of a page in one statement on the storage
connection's writer, never a replica, so a page read once an erasure has committed never reveals what it revoked. It
answers each field with:

- its value, typed as it was recorded: a string, a number, a boolean, `null`, a list or a map;
- `erased` only for a key whose tombstone a verified erasure row lists;
- `unreadable` for an unknown key, a key destroyed without a journalled erasure, a substituted key, a wrapped key that
  does not unwrap, or an envelope that fails its authentication, so an envelope moved to another entry or another path
  never reads.

It keeps no key once the page is read. `Privacy\SealedFieldReader` reads nothing and answers `encrypted` for every
field: bind it as `Contracts\FieldReader` where nothing should be decrypted in PHP, whatever a policy grants. A reader
an application binds is given every field of a page in one call to `readAll()`, only under the grant and only from rows
whose HMAC verified, and answers each, in order and in number; it keeps no state between calls and never answers with
the ciphertext. One that throws, or answers another count or anything but readings, costs the page's fields, each
`unreadable`, and is reported once, by its class alone.

Any map of exactly `v`, `k` and `c` in the properties or the context is read as an encryption envelope, even one an
application stored itself.

## Audited reads

Every page, count, export and verification is recorded under one of the package's own codes, below, before anything it
found leaves the package. The record is fail-closed whatever `failure.mode` says: when it cannot be written, the read
throws `Querying\AuditReadRefusedException` and returns nothing. That exception's message names classes and connections,
never a value, and it carries no previous exception.

Its cause is typed, so code never parses the message: `$reason` is a `Querying\Enums\ReadRefusal`, `$class` the class of
the store or the exception it names, and `$connection` the connection a transaction was open on, each `null` when the
cause names none.

```php
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;

try {
    $count = $trail->count();
} catch (AuditReadRefusedException $refusal) {
    if ($refusal->reason !== ReadRefusal::IN_TRANSACTION) {
        throw $refusal;
    }

    // read again once the transaction on $refusal->connection has committed
}
```

| `reason`             | Why the read was refused                                                                                |
|----------------------|---------------------------------------------------------------------------------------------------------|
| `reentrant`          | It was entered while a read, an audit record's write or its failure, or an event mapper was running     |
| `in_transaction`     | A transaction that could still roll its record back was open on `$connection`                           |
| `not_durable`        | In sync mode, the store `$class` does not say its return is durable                                     |
| `keeps_no_artifacts` | In sync mode, the store `$class` keeps no attachment, and every read's record carries one               |
| `unrecorded`         | Its record could not be written, or was never acknowledged                                              |
| `evidence_altered`   | Its record would not have kept its evidence exactly                                                     |
| `failed`             | Its statement, or formatting what it found, failed with the exception `$class`; the failure is recorded |
| `publish_failed`     | The export was journalled, and publishing its file failed with the exception `$class`; that is recorded |

- The record is the viewer's: its actor is the viewer, never the signed-in user, its category is `audit`, and its
  tenant is the scope's one tenant when the scope sees exactly one, and otherwise explicitly none, never an ambient
  tenant.
- Its properties are the read's evidence, kept exactly or the read is refused. The filters, the whole scope and, for a
  page, the position it read after and the id and HMAC of each entry returned are in an encrypted `disclosure`
  attachment, so a reader of the record sees fingerprints, never another tenant's ids.
- `query_fingerprint` and `scope_fingerprint` are HMAC-SHA256 under a key derived from the ring key `fingerprint_key`
  names, never a plain digest, so nobody without the key can recover a tenant, a user or a data subject by trying
  candidate filters until one matches. A disclosure carries a fresh random nonce, so the digest a reader is shown
  cannot be reversed either, even for a read that returned nothing.
- A page's `page` is `first` for the first page, `cursor` when it came with a cursor that gave no position, refused or
  never opened because the viewer was denied, and otherwise the position it read after, `{occurred_at, id}`, under a
  scope of exactly one tenant, whose record is that tenant's. Under any other scope the record has no tenant, so
  `page` is `next` and the position is in the disclosure alone, since it could be another tenant's entry.
- A read is `success`, or `denied` with `no_scope` or `cursor_rejected`, or `failure` with `policy_failed`,
  `query_failed` or `format_failed`: a statement or a row that fails is recorded, then refused with
  `AuditReadRefusedException` naming the class that failed.
- A trail is never read inside a transaction the application has open on the storage connection or the outbox
  connection. Such a read is refused with `AuditReadRefusedException` before the policy is asked or anything is
  queried, because its record, or a row it would show, could still be rolled back. The base transaction Laravel's
  testing helpers wrap a test in counts as committed, so a database test reads the trail as any other code does.
- In sync mode the record is stored by the audit store, which must say its return is durable and keep attachments, as
  the database store does; a read on any other store is refused before anything is queried. In outbox mode the record
  is a committed outbox row. A committed outbox row means the read was accepted, not yet delivered. The row is durable,
  and the store holds the record once a drain has run.
- A failed write is spilled, said as `AuditWriteFailed` and reported once, and the read throws.
- Reading the read records is a read like any other, and records exactly one more.
- A read refused before anything is queried is not recorded: one without a viewer, with a viewer that cannot be
  referenced, a malformed filter, a page size out of range, an export to a target that exists without `force` or to a
  directory whose filesystem cannot hold a hard link without `force`, an export on an engine it cannot read, an export
  while `export.chunk` is malformed, one inside an open transaction, and one entered while another read, an audit
  record's write or an event mapper is running.
- A record whose write leaves a transaction open, because code the write ran, such as a contributor, opened one, is
  never accepted as acknowledged, since a rollback could still remove it: the read is refused with the reason
  `in_transaction`.

Under `AuditLog::fake()` the fake acknowledges a read's record as it stores it, so a test using
`Testing\Concerns\InteractsWithAuditLog` asserts it as any other:

```php
AuditLog::fake();

AuditLog::trail()->visibleTo($auditor)->count();

$this->assertAudited('audit_log.trail_counted');
```

## Package codes

The package records every read, count, export and verification of the trail, and an export it could not publish, under
its own codes. Each is version 1 of its definition, in the `audit` category, with the viewer as its actor and no
subject, and keeps exactly the properties listed, dropping anything else. No application can record or redefine these
codes, but it can filter, describe and assert on them as it does on its own.

| Code                              | Outcomes                                                                                                          | Records                                                                                                                                                                                                                                 |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `audit_log.trail_read`            | `success`; `denied` (`no_scope`, `cursor_rejected`); `failure` (`policy_failed`, `query_failed`, `format_failed`) | A page read: `purpose`, `query_fingerprint`, `scope_fingerprint`, `fingerprint_key`, `policy`, `page`, `per_page`, `returned`, `reveal`, `fields` and `outcome`, with a `disclosure` attachment of the entries returned                 |
| `audit_log.trail_counted`         | `success`; `denied` (`no_scope`); `failure` (`policy_failed`, `query_failed`)                                     | A count: `purpose`, `query_fingerprint`, `scope_fingerprint`, `fingerprint_key`, `policy`, `returned` and `outcome`, with a `disclosure` attachment and no members                                                                      |
| `audit_log.trail_exported`        | `success`; `denied` (`no_scope`); `failure` (`policy_failed`, `query_failed`, `format_failed`)                    | An export: `purpose`, `query_fingerprint`, `scope_fingerprint`, `fingerprint_key`, `policy`, `format`, `returned`, `file_sha256` and `outcome`, with an `export` attachment, or a `disclosure` attachment and no members when it failed |
| `audit_log.export_verified`       | `success`, whatever the verification found; `denied` (`no_scope`); `failure` (`policy_failed`, `query_failed`)    | A verification of an export: `purpose`, `scope_fingerprint`, `fingerprint_key`, `policy`, `export_entry`, `verdict`, `findings` and `outcome`, with a `disclosure` attachment of the export's entry when it was found                   |
| `audit_log.export_publish_failed` | `failure` (`publish_failed`)                                                                                      | An export journalled and then not published: `export_entry` and `outcome`, with no attachment                                                                                                                                           |

## Exporting

`export()` writes the entries a viewer may see under the filters to a file, oldest first, journals the export and
publishes it with a bundle beside it, `<file>.manifest.json`:

```php
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;

$result = AuditLog::trail()
    ->visibleTo($auditor)
    ->forTenant($organisation)
    ->export(storage_path('app/audit/2026-q4.ndjson'), ExportFormat::NDJSON);

$result->entryId;          // the entry that journals the export
$result->fileSha256;       // the SHA-256 of the file's bytes
$result->acknowledgement;  // how the journal was acknowledged before anything was published
```

| Format   | Each line                                                                                     |
|----------|-----------------------------------------------------------------------------------------------|
| `ndjson` | the entry's signed envelope exactly as stored, whose HMAC verifies line by line: the evidence |
| `ocsf`   | the entry as an OCSF event, a projection for a security tool, its id in `metadata.uid`        |
| `cef`    | the entry as a CEF line, a projection for a security tool, its id in `externalId`             |

- The entries are read in one consistent snapshot, on a session of their own, in chunks of `export.chunk`, ascending by
  when they were recorded and then by id, so the file is a fixed set and memory grows with the chunk, never with the
  export. An entry recorded once the export has begun is not in it.
- The file is written to a temporary file beside the target, created exclusively and readable by its owner alone. The
  journal, `audit_log.trail_exported`, is written once the snapshot has ended, with the export's manifest as its
  `export` attachment, and must be acknowledged before anything is published: the bundle first, then the file.
- An existing target is refused unless `force` is given, and a target that appears while the export runs is never
  replaced without it. Publishing without `force` hard-links the file into place, so a directory on a filesystem that
  cannot hold a hard link, such as a FAT volume or an object-store mount, is refused before anything is read; export
  there with `force`, or to another directory and move the file. With `force` the previous file and bundle are set
  aside until both new ones are in place, and put back when publishing fails, so a previous export still verifies. A
  file that cannot be published is removed, `audit_log.export_publish_failed` is recorded naming the export entry, and
  the export throws.
- `ExportResult::$acknowledgement` is `stored` when the store holds the journal, and `accepted` when a committed outbox
  row does and a drain will deliver it.
- A viewer the policy denies is given an empty export, published and journalled as denied, exactly as an export that
  finds nothing is.
- The members of a bulk operation an exported entry references are not exported: the file holds each entry's
  descriptor of them, never the members.

`audit-log:export` is the same export from the console:

```bash
php artisan audit-log:export storage/app/audit/2026-q4.ndjson --viewer-type='App\Models\User' --viewer-id=42 --format=ocsf
```

| Option          | Effect                                                        |
|-----------------|---------------------------------------------------------------|
| `--viewer-type` | the type of the viewer the export is made for, required       |
| `--viewer-id`   | the id of the viewer the export is made for, required         |
| `--format`      | `ndjson`, the default, `ocsf` or `cef`                        |
| `--force`       | replace an existing file                                      |
| `--verify`      | verify the file and its bundle, below, instead of writing one |

`--viewer-type` and `--viewer-id` assert a reference; they do not prove who runs the command. Whoever can run artisan
can name any viewer, so the access policy decides what that viewer may see, and the console is guarded as any other
administrative access is. The command exits `0` once an export is published or a verification found nothing, `1` when
the read was refused or could not be recorded, or a verification found anything, and `2` for input it refuses before
anything is read.

## Verifying an export

`verifyExport()`, or `audit-log:export --verify`, checks an export and its bundle for a viewer, under the purpose
`verify`, and records the verification as `audit_log.export_verified` before its result is returned:

```php
$verification = AuditLog::trail()->visibleTo($auditor)->verifyExport(storage_path('app/audit/2026-q4.ndjson'));

$verification->isVerified();  // true only when nothing was found
$verification->findings;      // each finding, once, in the order the chain checks them
```

`audit_log.trail_exported` entries are protected from retention, so `--verify` keeps working while the database and
`app.key` live: `audit-log:prune` never deletes an export's entry or its `export` artifact, whatever the category
`audit` is kept for. The artifact's members are encrypted under `app.key`, so keep a rotated key in
`app.previous_keys` for as long as an export's verification is promised.

The verifying viewer's scope must reach the export entry: the category `audit`, and the exporter's single tenant, or
the entries of no tenant when the export's scope did not see exactly one. An entry outside the scope, and any entry at
all for a viewer the policy denies, is `entry_missing`, exactly as an entry that was never stored. The trail's filters
play no part. The entry and its artifact are looked up on the storage connection's writer, never a replica, so a
verification run before a replica has caught up never reports a stored entry as missing.

The chain runs in this order, and each step that fails is its own finding:

| Finding                  | What failed                                                                                    |
|--------------------------|------------------------------------------------------------------------------------------------|
| `bundle_malformed`       | the bundle is missing, or is not exactly a bundle this release writes                          |
| `entry_missing`          | the export entry is not stored, or the viewer may not see it                                   |
| `entry_unverifiable`     | the export entry is signed under a key the ring does not hold, or is not a well-formed row     |
| `entry_tampered`         | the export entry's HMAC does not match its content                                             |
| `entry_swapped`          | the entry found is not an export's journal, or not the one the bundle holds                    |
| `descriptor_mismatch`    | the descriptor the entry signed is not the bundle's, or not an export's                        |
| `artifact_missing`       | the artifact the descriptor names is not stored                                                |
| `artifact_swapped`       | the artifact is stored under another id than its descriptor signed, or names another entry     |
| `artifact_wrong_kind`    | the artifact is stored as another kind than its descriptor signed                              |
| `artifact_mismatch`      | the artifact counts other members, or holds another digest, than its descriptor signed         |
| `artifact_undecryptable` | the artifact cannot be decrypted with the application's keys                                   |
| `artifact_malformed`     | the artifact is no canonical export manifest                                                   |
| `artifact_tampered`      | the artifact is a canonical manifest, but not the one its descriptor signed                    |
| `manifest_mismatch`      | the manifest the bundle carries is not the one the journal holds                               |
| `file_mismatch`          | the file's SHA-256 is not its manifest's                                                       |
| `membership_mismatch`    | the file's lines, their ids, or its first and last positions are not its manifest's            |
| `line_malformed`         | a line is not a line of its format, or names no id                                             |
| `line_unverifiable`      | an NDJSON line is signed under a key the ring does not hold, or lacks a column its HMAC covers |
| `line_tampered`          | an NDJSON line's HMAC does not match its content                                               |

Each NDJSON line is checked by its own record and integrity versions, so an export from an earlier version still
verifies. An OCSF or a CEF export has no HMAC on its lines, so its file and membership digests are what is checked.
Verification proves the integrity of the row envelopes, not the completeness of the bulk members they reference.

Away from the application, an auditor checks an export with its bundle alone. The bundle is one canonical JSON object:
`bundle_version`, the artifact's `descriptor`, the export entry's signed columns as `entry`, and the canonical
`manifest`, as a string.

1. Decode the `manifest` string. The file's SHA-256 is its `file_sha256`. The SHA-256 of each line's id followed by a
   line feed, in file order, is its `membership_sha256`, over as many lines as its `lines`; the id is NDJSON's `id`,
   OCSF's `metadata.uid` and CEF's `externalId`.
2. The SHA-256 of the `manifest` string is the `digest` of the entry's signed descriptor,
   `properties._audit.manifest`, whose `kind` is `export`, and the entry's `file_sha256` is the manifest's.
3. Whoever holds the key recomputes the entry's HMAC, and each NDJSON line's, over the canonical encoding of every
   column but `hmac`, as `docs/design/integrity.md` sets out.

Anchoring is a later, observed state, never claimed at export time. The export entry is sealed and anchored with the
rest of the log, and `audit-log:verify` reports whether it has been.

## Answering a subject access request

An investigator answers a data subject's request for the records about them in three steps: selecting the subject's
activity and the entries holding the subject's encrypted fragments, with canonical exports kept as evidence of what was
selected; reviewing the selection before anything is given to the subject; and, when the subject asks for erasure too,
erasing the subject's keys. The canonical evidence export is not a copy for the data subject. It holds every column of
every entry, other people's references and data included, signed so that no part of it can be edited away.

For the run, bind a policy that lets the investigator, as the application authenticated them, read the subject's
activity with its encrypted fields revealed, and verify the exports it journals, and lets no one else see anything. A
fragment sealed under the subject's keys can be in an entry about anyone, and a policy is not told the trail's filters,
so while the investigator finds the fragments the policy lets them read every entry, and the selection asks for nothing
but `holdingDataOf()` under it:

<!-- procedure:policy -->

```php
<?php

namespace App\Audit;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

final readonly class SubjectAccessPolicy implements AuditAccessPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $investigator
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  bool  $fragments
     */
    public function __construct(

        /** The person answering the request, as the application authenticated them. */
        #[\SensitiveParameter]
        private Authenticatable $investigator,

        /** The person the request is about. */
        private Reference $subject,

        /** Whether the investigator is finding the entries that hold the subject's fragments. */
        private bool $fragments = false,
    ) {}

    /**
     * For the investigator, the audit category, where an export is journalled,
     * to verify an export; otherwise, with the encrypted fields revealed, the
     * subject's activity, as the actor or the subject of an entry, or every
     * entry while finding the subject's fragments, which can be in an entry
     * about anyone. Nothing for anyone else.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    #[\Override]
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        if ($viewer !== $this->investigator) {
            return AccessScope::none();
        }

        if ($purpose === ReadPurpose::VERIFY) {
            return AccessScope::all()->onlyCategories('audit');
        }

        $scope = $this->fragments ? AccessScope::all() : AccessScope::all()->onlyAbout($this->subject);

        return $scope->revealingEncryptedFields();
    }
}
```

Select the subject's activity, then the entries holding the subject's fragments, page by page, keeping an entry both
find once; export each selection to `$directory`, a directory of the investigator's own outside any public disk, and
verify each export, where `$investigator` is the authenticated user answering the request and `$subject` the person it
is about:

<!-- procedure:select -->

```php
use App\Audit\SubjectAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\Reference;

$you     = Reference::to($subject);
$entries = [];
$exports = [];

foreach (['activity' => false, 'fragments' => true] as $selection => $fragments) {
    app()->instance(AuditAccessPolicy::class, new SubjectAccessPolicy($investigator, $you, $fragments));

    $trail  = AuditLog::trail()->visibleTo($investigator);
    $trail  = $fragments ? $trail->holdingDataOf($you) : $trail;
    $cursor = null;

    do {
        $page   = $trail->cursorPaginate(100, $cursor);
        $cursor = $page->nextCursor;

        foreach ($page->entries as $entry) {
            $entries[$entry->id] ??= $entry;
        }
    } while ($cursor !== null);

    $exports[$selection] = $trail->export("{$directory}/{$selection}.ndjson");

    if (!$trail->verifyExport($exports[$selection]->path)->isVerified()) {
        throw new \RuntimeException('The evidence export does not verify.');
    }
}
```

Every page, export and verification is recorded under the investigator, as any read is, and each page's record says it
revealed encrypted fields and how many it showed in each state. The exports never decrypt: they keep every envelope as
stored.

Then review the selection. The grant reveals every encrypted field of each entry, whoever owns it, so an entry holding
the subject's fragment can show another owner's fragment beside it, such as a colleague's note on the subject's call.
The copy given to the subject keeps what is theirs, and leaves out every other person's reference, every other owner's
fragment and everything a person has not yet reviewed for third parties' data, the properties, the context and the
network details among them:

<!-- procedure:review -->

```php
use SineMacula\Laravel\AuditLog\Querying\Describer;

$describer = app(Describer::class);
$copy      = [];

foreach ($entries as $entry) {
    $copy[] = [
        'when'      => $entry->toArray()['occurred_at'],
        'what'      => $describer->describe($entry)->title,
        'outcome'   => $entry->outcome->value,
        'by_you'    => (bool) $entry->actor?->equals($you),
        'about_you' => (bool) $entry->subject?->equals($you),
    ];
}
```

An entry found only for the fragments it holds is neither by nor about the subject: which of its revealed values are
the subject's is for the review to establish before any of them is added to the copy.

When the subject asks for erasure too, erase their keys once the copy is made, on the authority of the request, where
`$case` is its reference in the investigator's own records:

<!-- procedure:erase -->

```php
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;

$authority = new Authority(Reference::to($investigator), 'gdpr.article_17', $case);
$erasure   = AuditLog::lifecycle()->erase($you, $authority);
```

From its commit every fragment sealed under the subject's keys reads `[ERASED]`, in the entries the selection found and
wherever else it is stored, and every entry, seal and evidence export still verifies: an export keeps the envelopes as
stored, and no key opens them any more. Other owners' fragments in the same entries are untouched. The erasure is all or
nothing: a hold, a preservation or an entry that fails its HMAC on any of the subject's keys refuses it with
`Lifecycle\ErasureRefusedException`, writing nothing, and `partial: true` destroys what nothing blocks and keeps the
rest, as [the privacy guide](privacy.md) sets out. The erasure revokes the subject's fragments in the live store; it is
complete only once the backups, replicas, exports, logs, destination stores and pending deliveries that guide lists no
longer hold them.

The selection finds the entries whose actor or subject is the subject, through `onlyAbout()`, and the entries holding a
fragment sealed under the subject's keys, through `holdingDataOf()`, and no more. Principal references and bulk members
are still not found: an entry whose principal or tenant is the subject and that holds no fragment of theirs, and a bulk
operation's members, are left to the investigator. A value about the subject kept in plaintext, rather than sealed under
their key, is found only where it sits in an entry by or about them, and no erasure reaches it. `holdingDataOf()` and
the erasure both need the package's key store: while a field encrypter other than the package's is bound,
`holdingDataOf()` is refused with a `\LogicException` and the erasure with `unsupported_encrypter`.

## Limits

- A queued listener runs outside the read guard: a listener that reads the trail ignores `audit_log.` codes. A
  synchronous listener of a read's own record that reads the trail is refused, and reported once, because its read
  would record a read whose listeners read again; a queued listener runs later, in a worker no guard can reach, so it
  must skip the package's codes itself, or each read it makes queues it again.
- A trail is never read inside a transaction the application has open on the storage connection or the outbox
  connection. Read it after the commit, from an after-commit callback or a queued job.
- On SQLite use WAL: in rollback-journal mode an export's snapshot blocks every writer's commit until it ends. In WAL
  mode the writers commit while it is open.
- The trail is not read-your-writes: a replica may lag, and a record waiting for a commit or a drain is not stored yet.
- `read.max_per_page`, set with `AUDIT_LOG_READ_MAX_PER_PAGE`, is the largest page a read may ask for, 100 by default
  and from 1 to 500. `export.chunk`, set with `AUDIT_LOG_EXPORT_CHUNK`, is how many entries an export reads per
  statement, 1000 by default and from 100 to 10000. A malformed value refuses the reads that use it, and
  `audit-log:check` reports it.
- A denied or disjoint read runs no statement, but a read that runs one takes as long as its plan does, so the time a
  read takes is not constant. What a PHP policy cannot stop, a direct query, a replica dump or a backup, is in
  `docs/design/threat-model.md`.
