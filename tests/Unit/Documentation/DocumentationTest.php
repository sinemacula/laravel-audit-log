<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Capture\ModelWatch;
use SineMacula\Laravel\AuditLog\Console\ExportCommand;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;
use SineMacula\Laravel\AuditLog\Querying\ExportVerification;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;
use SineMacula\Laravel\AuditLog\Testing\Concerns\InteractsWithAuditLog;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Stores\DocumentedSpillChannel;

/**
 * A drift guard for the README, the guides and the design notes: it catches an
 * omission or a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DocumentationTest extends TestCase
{
    /** @var list<class-string<\BackedEnum>> The public enums whose every value is documented. */
    private const array ENUMS = [
        Outcome::class,
        Origin::class,
        Provenance::class,
        FieldHandling::class,
        KeyOwner::class,
        IpMode::class,
        IdentifierMode::class,
        FailureMode::class,
        DeliveryMode::class,
        FailedOperation::class,
        EnvelopeFailure::class,
        IntegrityStatus::class,
        AnchorStatus::class,
        Finding::class,
        AnchorDriver::class,
        ReadPurpose::class,
        FieldState::class,
        ExportFormat::class,
        ExportFinding::class,
        Acknowledgement::class,
        ReadRefusal::class,
        JournalKind::class,
        HoldBasis::class,
        PruneStatus::class,
        ImportStatus::class,
        ImportFormat::class,
        ImportRejection::class,
        KeyState::class,
        MarkerTransition::class,
        ErasureRefusal::class,
        ErasureStatus::class,
        RewrapStatus::class,
    ];

    /** @var list<string> The sections of every design note, in order. */
    private const array SECTIONS = ['Purpose', 'Invariants', 'Success Path', 'Failure / Edge Cases', 'Implementation Anchors', 'Authoritative Tests', 'Change Triggers'];

    /** @var list<string> The design notes the package ships. */
    private const array NOTES = [
        'record-model.md',
        'event-definitions.md',
        'vocabulary.md',
        'storage.md',
        'integrity.md',
        'outcomes.md',
        'delivery.md',
        'event-model.md',
        'context-resolution.md',
        'redaction.md',
        'threat-model.md',
        'testing-helpers.md',
        'reading.md',
        'lifecycle.md',
        'privacy.md',
        'provider-composition.md',
    ];

    /** @var string The sentence the threat model opens with. */
    private const string KEY_MATCHING_LIMITS = 'Key matching cannot find a secret in free text or under an innocuous key; '
        . 'event definitions, which allowlist fields, are the remedy.';

    /** @var string The sentence the threat model states the brute force limit with. */
    private const string BRUTE_FORCE_LIMIT = 'A guessable identifier falls to brute force once the key leaks.';

    /** @var list<string> What the threat model says erasure does not promise, each in its own section. */
    private const array ERASURE_LIMITS = [
        'Database credentials can still destroy keys, key uses and markers; the package\'s cryptographic evidence makes '
            . 'unauthorised destruction, substitution or restoration detectable, never impossible',
        'An erasure, a hold and a trigger decide what the package does, and stop no one holding those credentials',
        'A wrapping key derived from `app.key` gives domain separation, not independence from `app.key`',
        'A decryption already returned cannot be recalled',
        'A restore from before an erasure brings the erased keys back',
        'without one, a full restore cannot be found',
        'An erasure revokes the owner\'s fields in the live store',
        'No store is claimed to hold no personal data: `privacy.md` lists each with what it holds and why',
        'The grant reveals every encrypted field of every entry a scope sees, whoever owns it',
    ];

    /** @var string The privacy note. */
    private const string PRIVACY_NOTE = '/docs/design/privacy.md';

    /** @var string The redaction note. */
    private const string REDACTION_NOTE = '/docs/design/redaction.md';

    /** @var string The threat model. */
    private const string THREAT_MODEL = '/docs/design/threat-model.md';

    /** @var string The delivery note. */
    private const string DELIVERY_NOTE = '/docs/design/delivery.md';

    /** @var string The provider composition note. */
    private const string COMPOSITION_NOTE = '/docs/design/provider-composition.md';

    /** @var string The event model. */
    private const string EVENT_MODEL = '/docs/design/event-model.md';

    /** @var string The outcomes note. */
    private const string OUTCOMES_NOTE = '/docs/design/outcomes.md';

    /** @var string The events guide. */
    private const string EVENTS_GUIDE = '/docs/guides/events.md';

    /** @var string The integrity note. */
    private const string INTEGRITY_NOTE = '/docs/design/integrity.md';

    /** @var string The operations guide. */
    private const string OPERATIONS_GUIDE = '/docs/guides/operations.md';

    /** @var list<string> The sections of the operations guide, in order. */
    private const array OPERATIONS_SECTIONS = [
        'Schedule',
        'Monitor',
        'Anchor outside the application',
        'Keys and their lifetimes',
        'Grants and triggers',
        'Sealing at volume',
        'Scale',
        'Compliance',
    ];

    /** @var list<string> What the threat model says integrity does not promise, each in its own section. */
    private const array INTEGRITY_LIMITS = [
        'An HMAC is not non-repudiation',
        'A compromised writer can still add fabricated records',
        'No seal proves that an uncaptured event happened',
        'A row deleted before its membership commits is undetectable',
        'deletion is detectable once membership is committed',
        'tail loss needs an independently retained witness',
        'Anyone holding the integrity key can forge seals',
        'Anchoring bounds exposure without removing it',
        'No timer bounds that exposure: a stopped scheduler or a backlog extends it',
        'Installing the package is not compliance',
        'Database credentials can still destroy rows; the package\'s cryptographic evidence makes unauthorised destruction detectable, never impossible',
        'the maintenance credentials can delete rows and the journal makes it detectable',
        '`--by-type` and `--by-id` prove nothing',
        'Imported rows assert what was accepted, not the truth of the event',
    ];

    /** @var string The automatic-capture guide. */
    private const string CAPTURE_GUIDE = '/docs/guides/automatic-capture.md';

    /** @var string The extending guide. */
    private const string EXTENDING_GUIDE = '/docs/guides/extending.md';

    /** @var list<string> The sections of the automatic-capture guide, in order. */
    private const array CAPTURE_SECTIONS = [
        'Laravel\'s authentication events',
        'Excluding guards',
        'Remember-me restores',
        'Gaps in core capture',
        'Gate denials',
        'Model changes',
        'Gaps in model capture',
        'Bulk operations',
        'When capture fails',
    ];

    /** @var list<string> The sections of the extending guide, in order. */
    private const array EXTENDING_SECTIONS = [
        'Extensibility', 'Mapping another package\'s events', 'Recording one row per sign-in', 'Correlation ids', 'Contributors', 'Guards without GuardHelpers',
    ];

    /** @var array<string, array{0: string, 1: string}> Each gap in capture, by what it is, as the section of the automatic-capture guide that states it and what it says. */
    private const array CAPTURE_GAPS = [
        'once'                         => ['Gaps in core capture', '`Auth::once()` and `Auth::onceUsingId()` authenticate for one request and fire no `Login`'],
        'token guards'                 => ['Gaps in core capture', 'Token guards that fire neither `Login` nor `Failed`'],
        'token issuance'               => ['Gaps in core capture', 'Record token issuance explicitly'],
        'events never recorded'        => ['Gaps in core capture', '`Attempting`, `Validated` and `Authenticated` are never recorded'],
        'a restore misclassified'      => ['Remember-me restores', 'an explicit `login()` on the same guard after a restore can be recorded as a restore'],
        'an ambiguous flow'            => ['Remember-me restores', 'A custom flow that is ambiguous in that way needs a mapper of its own'],
        'eventless gate checks'        => ['Gate denials', '`Gate::allowIf()`, `Gate::denyIf()` and callbacks that throw fire no `GateEvaluated`, so they record nothing'],
        'gate checks recorded by hand' => ['Gate denials', 'Record these explicitly'],
        'a subclass'                   => ['Model changes', 'a subclass is not watched through its parent'],
        'the query builder'            => ['Gaps in model capture', 'query-builder `update`, `delete`, `insert`, `upsert` and `increment`'],
        'a quiet save'                 => ['Gaps in model capture', '`saveQuietly`'],
        'no events'                    => ['Gaps in model capture', '`withoutEvents`'],
        'raw statements'               => ['Gaps in model capture', 'raw `DB::` statements'],
        'pivots'                       => ['Gaps in model capture', 'pivots without a `using()` model'],
        'custom model events'          => ['Gaps in model capture', 'custom `$dispatchesEvents` listeners that stop the fallback'],
        'the answer'                   => ['Gaps in model capture', '`covering()` is the answer'],
        'never truncated'              => ['Bulk operations', 'A larger one is refused, never truncated'],
        'an unsealed manifest'         => ['Bulk operations', 'until an entry is sealed, its artifact is checked by nothing'],
        'the host-fatal exception'     => ['When capture fails', 'The host-fatal exception'],
    ];

    /** @var string How the extending guide writes a correlation id. */
    private const string CORRELATION_FORMAT = '`<namespace>:<value>`';

    /** @var string The sentence the operations guide limits its measurements with. */
    private const string ONE_MACHINE = 'These measurements show one machine and claim nothing beyond it.';

    /** @var string A claim no measurement of one machine supports, however the words are wrapped. */
    private const string BEYOND_MEASUREMENT = '/\b(?:scales?|scalable|scaling|guarantee[sd]?|any\s+(?:size|volume|load)|unbounded|unlimited|production[\s-]ready'
        . '|fast\s+enough|blazing)\b/i';

    /** @var string What the disk anchor's guarantees rest on, on S3. */
    private const string OBJECT_LOCK = 'Object Lock in compliance mode with a retention period and a bucket policy denying version deletion';

    /** @var string Why Object Lock alone is not enough. */
    private const string NEW_VERSION = 'A new version hides an anchored object from an ordinary read, '
        . 'so the anchor also needs writes that cannot replace an existing object';

    /** @var string The sentence both the threat model and the delivery note state about the spill and the outbox. */
    private const string PERSONAL_DATA = 'The spill and the outbox hold personal data';

    /** @var list<string> The rows of the outcomes table, in order. */
    private const array OUTCOME_ROWS = [
        'after-commit-sync-report',
        'after-commit-sync-throw',
        'after-commit-none-open',
        'after-commit-outbox-same',
        'after-commit-outbox-same-throw',
        'after-commit-outbox-other',
        'immediately-sync-report',
        'immediately-sync-throw',
        'immediately-outbox',
        'transactional-sync',
        'transactional-outbox',
        'fail-closed-sync',
        'fail-closed-outbox',
        'fail-closed-transactional',
        'host-deadlock',
        'host-connection-lost',
        'aborted-postgres-host',
        'failed-finalise',
        'inside-a-store',
        'inside-a-store-strict',
        'drain-transient',
        'drain-final',
        'drain-undecryptable',
        'captured-report',
        'captured-host-fatal',
        'captured-model-after-commit',
        'read-sync',
        'read-outbox',
        'read-open-transaction',
        'read-failed-write',
    ];

    /** @var list<string> The facade calls the documentation may show before they ship. */
    private const array PLANNED_CALLS = [];

    /** @var string The sentence the design index ends with. */
    private const string CLOSING = 'These documents are secondary to the code and tests, not a replacement for them. '
        . 'If a note and a cited test disagree, the test should be treated as authoritative until the mismatch is resolved.';

    /** @var list<string> The code prefixes the vocabulary reserves. */
    private const array RESERVED_PREFIXES = ['authentication.', 'session.', 'account.', 'authorization.', 'mfa.', 'sso.', 'audit_log.'];

    /** @var list<string> Laravel's own configuration files, which an example may read. */
    private const array LARAVEL_CONFIG = ['app', 'auth', 'cache', 'database', 'filesystems', 'logging', 'queue', 'session'];

    /** @var string The package's configuration key. */
    private const string CONFIG_KEY = 'audit-log';

    /** @var string The package's namespace, the one the suite's namespace may be followed by in an example. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string A string-literal argument, single or double quoted. */
    private const string LITERAL = '(?:\'([^\'\\\]*)\'|"([^"\\\]*)")';

    /** @var string The ways of calling something fail-closed, however the words are wrapped. */
    private const string FAIL_CLOSED = '/\bfail(?:s|ed|ing)?[\s-]+closed\b/i';

    /** @var string A citation of what is kept out of the repository: the requirements, the backlog or a build file. */
    private const string LOCAL_ONLY = '/FEATURES\.md|BACKLOG\.md|\bAUDIT-[A-Z]+\.\d|\bBL-\d|\.sinemacula\b|\bm\d+-design\b|§/';

    /** @var string A way of saying a failed record is not true, which it can be even when the business change rolls back, however the words are wrapped. */
    private const string NOT_TRUE = '/\b(?:the|a|its|that)\s+(?:failed\s+|spilled\s+)?record\s+(?:is|was)\s+(?:not|never)\s+true\b/i';

    /** @var string A citation of how the work was divided, which means nothing to a reader of the repository. */
    private const string MILESTONE = '/\bmilestones?\b|\bM[1-9]\b/';

    /** @var string Words describing a transition from a release, and none exists. */
    private const string TRANSITION = '/\bbreaking change|\bdeprecat|\bupgrade notes?\b|\bbackward[s]?[\s-]compat/i';

    /** @var string The name of another package of the suite, in prose as much as in code. */
    private const string SIBLING = '/\blaravel-(?:authentication|authorization|mfa|sso|iam)\b/i';

    /** @var string The reading guide. */
    private const string READING_GUIDE = '/docs/guides/reading.md';

    /** @var string The reading note. */
    private const string READING_NOTE = '/docs/design/reading.md';

    /** @var list<string> The sections of the reading guide, in order. */
    private const array READING_SECTIONS = [
        'Reading the trail',
        'Viewers and the access policy',
        'Scopes',
        'Pages and cursors',
        'Counting',
        'Describing entries',
        'Encrypted fields',
        'Audited reads',
        'Package codes',
        'Exporting',
        'Verifying an export',
        'Answering a subject access request',
        'Limits',
    ];

    /** @var array<string, string> What the reading guide must say, by what each statement is about. */
    private const array READING_STATEMENTS = [
        'assertion'        => 'The application authenticates the viewer: a `Reference` viewer is an assertion, not authentication.',
        'onlyAbout'        => '`onlyAbout()` selects rows by actor or subject only; it is not a complete disclosure policy.',
        'late rows'        => 'a row inserted later into an interval already walked may be missed',
        'read-your-writes' => 'the trail is not read-your-writes',
        'accepted'         => 'A committed outbox row means the read was accepted, not yet delivered.',
        'bulk members'     => 'Verification proves the integrity of the row envelopes, not the completeness of the bulk members they reference.',
        'anchoring'        => 'Anchoring is a later, observed state, never claimed at export time.',
        'subject copy'     => 'The canonical evidence export is not a copy for the data subject.',
        'console viewer'   => '`--viewer-type` and `--viewer-id` assert a reference; they do not prove who runs the command.',
        'queued listener'  => 'A queued listener runs outside the read guard: a listener that reads the trail ignores `audit_log.` codes.',
        'wal'              => 'On SQLite use WAL: in rollback-journal mode an export\'s snapshot blocks every writer\'s commit until it ends.',
        'open transaction' => 'A trail is never read inside a transaction the application has open on the storage connection or the outbox connection.',
        'no grant'         => 'Without the grant no reader is asked, and every sealed field shows `[ENCRYPTED]`.',
        'grant reveals'    => 'The grant reveals every encrypted field of every entry the scope sees, whoever owns it: it is not an owner-specific projection.',
        'grant binds'      => 'The grant is part of the scope\'s normalised form and fingerprint',
        'no decryption'    => 'A count and an export never decrypt',
        'reveal evidence'  => 'A page read under the grant records `reveal` and `fields`',
        'recall'           => 'A decryption already returned cannot be recalled.',
        'authenticated'    => 'Under the grant, each row\'s HMAC is verified before any field of it is read.',
        'unauthenticated'  => 'shows every sealed field it holds as `[UNREADABLE]`, and none of them reaches the reader',
        'default reader'   => 'The package binds `Privacy\SubjectKeyFieldReader`, which reads the keys of a page in one statement',
        'never a replica'  => 'on the storage connection\'s writer, never a replica, so a page read once an erasure has committed never reveals',
        'erased only'      => '`erased` only for a key whose tombstone a verified erasure row lists',
        'sealed reader'    => '`Privacy\SealedFieldReader` reads nothing and answers `encrypted` for every field',
        'reader contract'  => 'only under the grant and only from rows whose HMAC verified, and answers each, in order and in number',
        'holding filter'   => '`holdingDataOf()` keeps the entries holding a fragment sealed under one of the owner\'s keys',
    ];

    /** @var list<string> What the subject access procedure must say of what it finds, reveals and erases. */
    private const array PROCEDURE_STATEMENTS = [
        'The canonical evidence export is not a copy for the data subject.',
        'a policy is not told the trail\'s filters',
        'The grant reveals every encrypted field of each entry, whoever owns it',
        'leaves out every other person\'s reference, every other owner\'s fragment',
        'From its commit every fragment sealed under the subject\'s keys reads `[ERASED]`',
        'Other owners\' fragments in the same entries are untouched.',
        'it is complete only once the backups, replicas, exports, logs, destination stores and pending deliveries',
        'through `onlyAbout()`, and the entries holding a fragment sealed under the subject\'s keys, through `holdingDataOf()`',
        'Principal references and bulk members are still not found',
        'no erasure reaches it',
    ];

    /** @var array<string, string> What the threat model says a PHP access policy cannot do, by what each statement is about. */
    private const array PHP_POLICY_LIMITS = [
        'direct access'  => 'A PHP policy cannot stop direct SQL, a replica dump or a backup',
        'database roles' => 'database roles and the database\'s own auditing must cover them',
        'AuditEntry'     => 'Reading `AuditEntry` directly bypasses the trail, as any query does',
        'timing'         => 'Plan-dependent timing is not constant',
    ];

    /** @var list<string> What the reading note says the read path leaves for others to build. */
    private const array READING_SEAMS = [
        'An owner-specific projection for a subject access request',
        'the other owners\' fragments the selected entries hold are reviewed by the investigator',
        'A copy for the data subject',
        'built from revealed pages, never from an export',
    ];

    /** @var list<string> What the reading note's seams must not name, since the package ships them. */
    private const array SHIPPED_SEAMS = ['FieldReader', 'Owner discovery'];

    /** @var string The rule that keeps the export evidence verifiable, which the reading note and the reading guide both state. */
    private const string EXPORT_EVIDENCE = '`audit_log.trail_exported` entries are protected from retention, so `--verify` keeps working while the database and `app.key` live';

    /** @var list<class-string> The classes whose methods the reading guide's examples call. */
    private const array READING_CLASSES = [
        AuditTrail::class,
        AccessScope::class,
        TrailPage::class,
        TrailEntry::class,
        Describer::class,
        ExportVerification::class,
        Reference::class,
        FakeAuditStore::class,
        InteractsWithAuditLog::class,
        Recorder::class,
        AuditLifecycle::class,
        Container::class,
    ];

    /** @var list<string> The calls the reading guide's examples make that are the example application's own, or Carbon's, answered by magic. */
    private const array APPLICATION_CALLS = ['isAuditor', 'subDays'];

    /** @var string A way of saying the immediate path is outside the caller's transaction, which it is not, however the words are wrapped. */
    private const string OUTSIDE_THE_CALLER = '/\boutside\s+(?:of\s+)?(?:the|a|any)\s+caller(?:\'|’)?s?\s+transactions?\b/iu';

    /** @var ?string The README, the guides and the design notes, read once. */
    private static ?string $documentation = null;

    /**
     * Rows of `[enum value, enum]`: every value of the documented public enums.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEnumValues(): iterable
    {
        foreach (self::ENUMS as $enum) {
            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [$case->value, $enum];
            }
        }
    }

    /**
     * Every value of those enums is named in the documentation, in code type.
     *
     * @param  string  $value
     * @param  string  $enum
     * @return void
     */
    #[DataProvider('provideEnumValues')]
    public function testEveryEnumValueIsDocumented(string $value, string $enum): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $value . '`'), sprintf('The documentation does not name the %s value `%s`.', $enum, $value));
    }

    /**
     * Rows of `[key]`: every configuration key the package config ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConfigurationKeys(): iterable
    {
        $config = require self::root() . '/config/audit-log.php';

        self::assertIsArray($config);

        foreach (self::leafKeys($config) as $key) {
            yield $key => [$key];
        }
    }

    /**
     * Every configuration key is named by its full path in the documentation.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConfigurationKeys')]
    public function testEveryConfigurationKeyIsDocumented(string $key): void
    {
        self::assertSame([], self::undocumentedKeys([$key], self::documentation()), sprintf('The documentation does not name the configuration key `%s`.', $key));
    }

    /**
     * A planted leaf fails; only a full-path mention documents a leaf.
     *
     * @return void
     */
    public function testAPlantedUndocumentedLeafFailsTheCheck(): void
    {
        $config = require self::root() . '/config/audit-log.php';

        self::assertIsArray($config);
        self::assertIsArray($config['monitor']);

        $config['monitor']['planted_minutes'] = 5;
        $config['planted']                    = ['section' => ['leaf' => null]];

        $keys = self::leafKeys($config);

        self::assertContains('monitor.planted_minutes', $keys);
        self::assertContains('planted.section.leaf', $keys);
        self::assertSame(['monitor.planted_minutes', 'planted.section.leaf'], self::undocumentedKeys($keys, self::documentation()));
        self::assertSame(['monitor.planted_minutes'], self::undocumentedKeys(['monitor.planted_minutes'], 'The `planted_minutes` and `monitor.planted_minutes.extra` settings.'));
    }

    /**
     * Rows of `[file]`: every design note the package ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDesignNotes(): iterable
    {
        foreach (self::NOTES as $note) {
            yield $note => [$note];
        }
    }

    /**
     * Every design note the package ships exists.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideDesignNotes')]
    public function testEveryDesignNoteExists(string $note): void
    {
        self::assertFileExists(self::root() . '/docs/design/' . $note);
    }

    /**
     * Rows of `[file]`: every design note in docs/design but the index.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNoteFiles(): iterable
    {
        foreach (self::noteFiles() as $note) {
            yield $note => [$note];
        }
    }

    /**
     * Every design note has a Title Case heading and the standard sections.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideNoteFiles')]
    public function testEveryDesignNoteHasTheStandardSections(string $note): void
    {
        $prose = self::withoutCodeBlocks(self::read('/docs/design/' . $note));

        preg_match_all('/^# (.+)$/m', $prose, $titles);
        preg_match_all('/^## (.+)$/m', $prose, $sections);

        self::assertCount(1, $titles[1], sprintf('%s does not have exactly one title.', $note));
        self::assertStringStartsWith('# ' . $titles[1][0], ltrim($prose), sprintf('%s does not open with its title.', $note));
        self::assertTrue(self::isTitleCase($titles[1][0]), sprintf('The title of %s is not in Title Case.', $note));

        $found    = $sections[1];
        $extra    = array_slice($found, 4, max(0, count($found) - count(self::SECTIONS)));
        $standard = [...array_slice($found, 0, 4), ...array_slice($found, 4 + count($extra))];

        self::assertSame(self::SECTIONS, $standard, sprintf('%s does not have the standard sections in order.', $note));
        self::assertSame([], array_values(array_intersect($extra, self::SECTIONS)), sprintf('%s repeats a standard section.', $note));
    }

    /**
     * The design index lists the sections and every note, and ends with the
     * standard sentence.
     *
     * @return void
     */
    public function testTheDesignIndexListsEveryNoteAndEndsWithTheStandardSentence(): void
    {
        $index = self::read('/docs/design/README.md');

        preg_match_all('/^- `([^`]+\.md)`: /m', $index, $notes);
        preg_match_all('/^- `([^`]+)`$/m', $index, $sections);

        $listed = $notes[1];
        $files  = self::noteFiles();

        sort($listed);
        sort($files);

        $paragraphs = preg_split('/\n\s*\n/', trim($index)) ?: [];

        self::assertStringStartsWith("# Design Notes\n", $index);
        self::assertSame(self::SECTIONS, $sections[1], 'The design index does not list the standard sections in order.');
        self::assertSame($files, $listed, 'The design index does not list exactly the notes in docs/design.');
        self::assertSame(self::CLOSING, preg_replace('/\s+/', ' ', (string) end($paragraphs)), 'The design index does not end with the standard sentence.');
    }

    /**
     * Rows of `[file]`: every design note in docs/design but the index.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCitingNotes(): iterable
    {
        yield from self::provideNoteFiles();
    }

    /**
     * Every test file and method a note cites exists, and every note cites one.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideCitingNotes')]
    public function testEveryCitedTestExists(string $note): void
    {
        $cited = self::citedTests(self::section(self::read('/docs/design/' . $note), 'Authoritative Tests'));

        self::assertNotSame([], $cited, sprintf('%s cites no test.', $note));

        $missing = [];

        foreach ($cited as $file => $methods) {

            $path = self::root() . '/' . $file;

            if (!is_file($path)) {
                $missing[] = $file;

                continue;
            }

            $source = (string) file_get_contents($path);

            foreach ($methods as $method) {

                if (str_contains($source, 'function ' . $method . '(')) {
                    continue;
                }

                $missing[] = $file . ' ' . $method;
            }
        }

        self::assertSame([], $missing, sprintf('%s cites tests that do not exist.', $note));
    }

    /**
     * The citation scanner pairs each method with the file cited before it.
     *
     * @return void
     */
    public function testTheCitationScannerPairsEachMethodWithItsFile(): void
    {
        self::assertSame(['?' => ['testOrphan']], self::citedTests("- `testOrphan` in `src/Records/EventCode.php`\n"));
        self::assertSame(['tests/Unit/AnyTest.php' => ['testOne', 'testTwo']], self::citedTests("- `tests/Unit/AnyTest.php` `testOne`,\n  `testTwo`: `null`\n"));
    }

    /**
     * Rows of `[prefix]`: every code prefix the vocabulary reserves.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedPrefixes(): iterable
    {
        foreach (self::RESERVED_PREFIXES as $prefix) {
            yield $prefix => [$prefix];
        }
    }

    /**
     * Every reserved prefix has a row in the vocabulary's table.
     *
     * @param  string  $prefix
     * @return void
     */
    #[DataProvider('provideReservedPrefixes')]
    public function testEveryReservedPrefixIsInTheVocabulary(string $prefix): void
    {
        $row = '/^\| `' . preg_quote($prefix, '/') . '` +\|/m';

        self::assertSame(1, preg_match($row, self::read('/docs/design/vocabulary.md')), sprintf('The vocabulary has no row for `%s`.', $prefix));
    }

    /**
     * The prefix event codes refuse is one of the reserved prefixes.
     *
     * @return void
     */
    public function testThePackagePrefixIsTheOneEventCodesReserve(): void
    {
        self::assertContains(EventCode::RESERVED_PREFIX, self::RESERVED_PREFIXES);
    }

    /**
     * Every shipped code sits under a reserved prefix.
     *
     * @return void
     */
    public function testEveryShippedCodeIsUnderAReservedPrefix(): void
    {
        self::assertSame([], self::codesOutsideTheReservedPrefixes(self::shippedCodes()), 'The package ships codes outside the reserved prefixes.');
    }

    /**
     * Every code the package ships is named in the documentation, in code type.
     *
     * @return void
     */
    public function testEveryShippedCodeIsDocumented(): void
    {
        $undocumented = array_values(array_filter(self::shippedCodes(), static fn (string $code): bool => !str_contains(self::documentation(), '`' . $code . '`')));

        self::assertSame([], $undocumented, 'The documentation does not name every shipped code.');
    }

    /**
     * The shipped-code check reads every case of a defining enum.
     *
     * @return void
     */
    public function testTheShippedCodeCheckReadsEveryCaseOfADefiningEnum(): void
    {
        $codes = self::codesOf([InvoiceActivity::class, Outcome::class, self::class]);

        self::assertSame(['invoice.approved', 'invoice.refund_failed'], $codes);
        self::assertSame($codes, self::codesOutsideTheReservedPrefixes($codes));
        self::assertSame([], self::codesOutsideTheReservedPrefixes(['audit_log.pruned', 'session.created']));
        self::assertSame(['audit_logs.pruned', 'app.session.created'], self::codesOutsideTheReservedPrefixes(['audit_logs.pruned', 'app.session.created']));
    }

    /**
     * Every example code is a valid event code under no reserved prefix.
     *
     * @return void
     */
    public function testEveryExampleCodeIsValidAndNeutral(): void
    {
        $codes   = self::exampleCodesIn(self::codeBlocks());
        $invalid = [];

        foreach ($codes as $code) {
            try {
                EventCode::of($code);
            } catch (\InvalidArgumentException) {
                $invalid[] = $code;
            }
        }

        self::assertNotSame([], $codes, 'The documentation shows no example code.');
        self::assertSame([], $invalid, 'The documentation shows invalid event codes.');
        self::assertSame([], self::codesUnderTheReservedPrefixes($codes), 'The documentation shows codes under a reserved prefix.');
    }

    /**
     * The example scanner finds every code argument and enum case value only.
     *
     * @return void
     */
    public function testTheExampleScannerFindsEveryFormOfCode(): void
    {
        $example = <<<'PHP'
            AuditLog::record('invoice.approved', subject: $invoice);
            AuditLog::event("user.suspended")->on($user)->record();
            AuditLog::accessed( 'patient.record_viewed', subject: $record);
            AuditLog::event('invoice.exported')->covering($invoices);
            EventDefinition::for('invoice.voided')->category('finance');
            EventDefinition::for($this)->retain('amount');
            Event::dispatch('not.a_code');
            $builder->recorded('not.a_code');
            case APPROVED = 'invoice.refunded';
            case Pending = 'not.a_case';
            // case DRAFT = 'invoice.drafted';
            PHP;

        $codes = ['invoice.approved', 'user.suspended', 'patient.record_viewed', 'invoice.exported', 'invoice.voided', 'invoice.refunded', 'invoice.drafted'];

        self::assertSame($codes, self::exampleCodesIn($example));
    }

    /**
     * No code block names another package of the suite or its configuration.
     *
     * @return void
     */
    public function testNoExampleNamesAnotherSuitePackage(): void
    {
        self::assertSame([], self::foreignNamesIn(self::codeBlocks()), 'The documentation\'s examples name another package of the suite.');
    }

    /**
     * The neutrality scanner finds every foreign name, never the package's own.
     *
     * @return void
     */
    public function testTheNeutralityScannerFindsEveryForeignName(): void
    {
        $example = <<<'PHP'
            use SineMacula\Laravel\AuditLog\Facades\AuditLog;
            use SineMacula\Laravel\Other\Thing;
            $class = 'SineMacula\\Laravel\\Another\\Thing';
            $other = \SineMacula\Laravel\AuditLogger\Thing::class;
            composer require sinemacula/laravel-audit-log sinemacula/laravel-other
            $connection = config('audit-log.storage.connection');
            $driver = config("session.driver");
            $prefix = config('other.prefix');
            $value = Config::get('another.key');
            config(['third.key' => true]);
            PHP;

        self::assertSame([
            'SineMacula\Laravel\Other',
            'SineMacula\\\Laravel\\\Another',
            'SineMacula\Laravel\AuditLogger',
            'sinemacula/laravel-other',
            'config: other',
            'config: another',
            'config: third',
        ], self::foreignNamesIn($example));
    }

    /**
     * Rows of `[event class]`: every event the package dispatches.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEvents(): iterable
    {
        foreach (glob(self::root() . '/src/Events/*.php') ?: [] as $file) {

            $class = self::PACKAGE_NAMESPACE . 'Events\\' . basename($file, '.php');

            if (!is_a($class, AuditLogEvent::class, true) || (new \ReflectionClass($class))->isAbstract()) {
                continue;
            }

            yield basename($file, '.php') => [$class];
        }
    }

    /**
     * Every event the package dispatches has a row in the events table.
     *
     * @param  string  $class
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEveryEventIsInTheEventsTable(string $class): void
    {
        self::assertTrue(self::hasEventRow(self::documentation(), $class), sprintf('The events table has no row for %s.', $class));
    }

    /**
     * An event's row must start with its whole class name.
     *
     * @return void
     */
    public function testTheEventRowMustNameTheWholeClass(): void
    {
        $class = AuditRecorded::class;

        self::assertTrue(self::hasEventRow("| Event |\n| `{$class}` | The store accepted it |\n", $class));
        self::assertFalse(self::hasEventRow("`{$class}` is dispatched.\n", $class));
        self::assertFalse(self::hasEventRow("| The store accepted it | `{$class}` |\n", $class));
        self::assertFalse(self::hasEventRow("| `{$class}Later` | Later |\n", $class));
    }

    /**
     * Rows of `[method]`: every public method the recorder declares.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRecorderMethods(): iterable
    {
        foreach (self::callsDeclaredOn(Recorder::class) as $method) {
            yield $method => [$method];
        }
    }

    /**
     * Every method the recorder declares is shown being called.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideRecorderMethods')]
    public function testEveryRecorderMethodIsDocumented(string $method): void
    {
        self::assertSame(1, preg_match('/(::|->|`)' . $method . '\(/', self::documentation()), sprintf('The documentation does not show %s().', $method));
    }

    /**
     * Rows of `[method]`: each public method the facade adds to the recorder's.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFacadeMethods(): iterable
    {
        foreach (self::callsDeclaredOn(AuditLog::class) as $method) {
            yield $method => [$method];
        }
    }

    /**
     * Every method the facade declares of its own is shown being called on it.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideFacadeMethods')]
    public function testEveryFacadeMethodIsDocumented(string $method): void
    {
        self::assertContains($method, self::auditLogCallsIn(self::documentation()), sprintf('The documentation does not show AuditLog::%s().', $method));
    }

    /**
     * Every `AuditLog::` call shown is the recorder's, the facade's or planned.
     *
     * @return void
     */
    public function testEveryAuditLogCallTheDocumentationShowsExists(): void
    {
        $unknown = array_values(array_diff(self::auditLogCallsIn(self::documentation()), self::knownAuditLogCalls()));

        self::assertSame([], $unknown, 'The documentation shows AuditLog calls that do not exist.');
    }

    /**
     * The call scanner finds each facade call once, however it is written.
     *
     * @return void
     */
    public function testTheCallScannerFindsEveryAuditLogCall(): void
    {
        $text = <<<'EOD'
            AuditLog::record('invoice.approved');
            Use `AuditLog::event()` to build one up.
            \SineMacula\Laravel\AuditLog\Facades\AuditLog::accessed('document.downloaded');
            $fake = AuditLog::fake ();
            AuditLog::
                contribute(OrganisationContributor::class);
            AuditLog::record('invoice.voided');
            $class = AuditLog::class;
            NotAuditLog::bulk();
            $AuditLog::map();
            AuditLog->capture();
            EOD;

        self::assertSame(['record', 'event', 'accessed', 'fake', 'contribute'], self::auditLogCallsIn($text));
    }

    /**
     * Only the package's own and the planned calls are allowed, by exact name.
     *
     * @return void
     */
    public function testTheKnownCallsAreOnlyThePackagesOwn(): void
    {
        $known = self::knownAuditLogCalls();

        foreach (['record', 'event', 'accessed', 'define', 'contribute', 'fake', 'recorder', 'capture', 'map', 'watch'] as $call) {
            self::assertContains($call, $known);
        }

        foreach (['__construct', '__callStatic', 'swap', 'spy', 'shouldReceive', 'getFacadeRoot', 'getFacadeAccessor', 'Record', 'bulk'] as $call) {
            self::assertNotContains($call, $known);
        }
    }

    /**
     * No planned call has shipped, so the list cannot outlive its methods.
     *
     * @return void
     */
    public function testNoPlannedCallHasShipped(): void
    {
        self::assertSame([], array_values(array_intersect(self::PLANNED_CALLS, self::callsDeclaredOn(Recorder::class))));
        self::assertSame([], array_values(array_intersect(self::PLANNED_CALLS, self::callsDeclaredOn(AuditLog::class))));
    }

    /**
     * The context note states the proxy prerequisites of trusting a header.
     *
     * @return void
     */
    public function testTheContextNoteStatesTheProxyPrerequisite(): void
    {
        $note = self::prose('/docs/design/context-resolution.md');

        self::assertStringContainsString('`TrustProxies` must be configured', $note);
        self::assertStringContainsString('`isFromTrustedProxy()` checks only the immediate peer', $note);
        self::assertStringContainsString('the trusted edge must overwrite or validate these headers', $note);
    }

    /**
     * The context note says what a job carries is readable in the payload.
     *
     * @return void
     */
    public function testTheContextNoteStatesThatHiddenContextIsNotEncrypted(): void
    {
        self::assertStringContainsString('Hidden Context travels in the queue payload unencrypted', self::prose('/docs/design/context-resolution.md'));
    }

    /**
     * Rows of `[note, statement]`: what each note must state.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRequiredStatements(): iterable
    {
        $context     = '/docs/design/context-resolution.md';
        $testing     = '/docs/design/testing-helpers.md';
        $definitions = '/docs/design/event-definitions.md';
        $record      = '/docs/design/record-model.md';
        $storage     = '/docs/design/storage.md';
        $integrity   = '/docs/design/integrity.md';

        yield from [
            'the actor is never loaded'           => [$context, 'never through `user()`'],
            'guards with the trait only'          => [$context, '`GuardHelpers` trait'],
            'a foreign guard is asked one thing'  => [$context, '`hasUser()` and nothing else'],
            'the guard goes with the actor'       => [$context, 'The guard, principal, tenant and session go with the ambient or carried actor only'],
            'a record before the middleware'      => [$context, 'before the `auth` middleware'],
            'outside any frame'                   => [$context, 'Outside any frame the origin is `console`'],
            'a nested call without events'        => [$context, '`$this->call()` inside a command emits no command event'],
            'no claimed id'                       => [$context, 'No claimed id is kept'],
            'the snapshot is not authentication'  => [$context, 'who started the work, not current authentication'],
            'only the package is reset'           => [$context, 'Only the package\'s own state is ever reset'],
            'a guard a job leaves signed in'      => [$context, 'still holding the identical object counts as holding nobody'],
            'a listener on the end of a job'      => [$context, 'still inside the frame'],
            'a record before trusting a proxy'    => [$context, 'in global middleware ahead of `TrustProxies`'],
            'the recorder is stateless'           => [$context, 'The recorder is stateless'],
            'registration at boot'                => [$context, 'not from a `booted()` callback'],
            'the fake is no engine'               => [$testing, 'no transaction engine'],
            'field rules apply at capture'        => [$testing, 'Field rules apply at capture'],
            'the failing fake'                    => [$testing, '`FakeAuditStore::failing(\Throwable)`'],
            'the first assertion'                 => [$testing, '`assertAudited($code, ?Closure)`'],
            'the second assertion'                => [$testing, '`assertNotAudited($code, ?Closure)`'],
            'the third assertion'                 => [$testing, '`assertNothingAudited()`'],
            'the fourth assertion'                => [$testing, '`assertAuditedTimes($code, $times)`'],
            'what the store received'             => [$testing, '`finalised()`, what the store received'],
            'faking every event'                  => [$testing, '`Event::fake([AuditRecorded::class])`'],
            'skipping the middleware'             => [$testing, '`withoutMiddleware()` means no HTTP frame'],
            'console events in a test'            => [$testing, '`WithConsoleEvents` is needed for command frames'],
            'a record after a request'            => [$testing, 'A record made after `$this->get()`'],
            'the test wrapper'                    => [$testing, '`transactional()` counts a `DatabaseTransactions` wrapper'],
            'registering in a test'               => [$testing, '`$app->booting()`'],
            'minimising in the pipeline'          => [$context, '`Privacy\RecordMinimiser` minimises it'],
            'a filled value is minimised'         => [$context, 'A filled value is minimised too'],
            'the walker reaches a nested rule'    => [$definitions, 'keeps `customer.email` and drops the rest of `customer`'],
            'the rules apply at capture'          => [$definitions, 'the rules apply at capture'],
            'what the metadata holds'             => [$record, 'it holds `note`, `identifier_hash` and `omitted`'],
            'an owned note is sealed'             => [$record, 'it is sealed through `Contracts\FieldEncrypter`'],
            'the record takes the minimised'      => [$record, '`AuditRecord::fromPending()` takes the minimised value'],
            'the id is minted first'              => [$record, 'The id is minted before the record is minimised, never after'],
            'the record takes the minted id'      => [$record, '`AuditRecord::fromPending()` takes the id it was given'],
            'values are sealed for the entry'     => [$record, 'Minimising seals each encrypted value for the record\'s entry id'],
            'an exemption is an assumption'       => [self::REDACTION_NOTE, 'An exemption assumes non-secret metadata'],
            'an exempt container is kept'         => [self::REDACTION_NOTE, 'an exempt container\'s scalar values are kept'],
            'the remedy is a field rule'          => [self::REDACTION_NOTE, 'the remedy is an explicit field rule'],
            'policy before transform'             => [self::REDACTION_NOTE, 'selects the policy first and transforms the value after it'],
            'a long container is dropped'         => [self::REDACTION_NOTE, 'A container whose canonical JSON is longer than 1024 bytes is dropped and diagnosed'],
            'a 6to4 address keeps its /24'        => [self::REDACTION_NOTE, 'A `2002::/16` address truncates to its /40'],
            'an invalid address is no refusal'    => [self::REDACTION_NOTE, 'An invalid address is `null` in every mode and adds `$ip`'],
            'the minimum of the properties'       => [self::REDACTION_NOTE, 'at least 8192'],
            'the minimum of the context'          => [self::REDACTION_NOTE, 'at least 1024'],
            'what the count counts'               => [self::REDACTION_NOTE, '`count` counts removed branches'],
            'the note is not protected'           => [self::REDACTION_NOTE, 'A note is not protected'],
            'a mapped address is its IPv4'        => [self::REDACTION_NOTE, 'an IPv4-mapped address is its IPv4 address'],
            'the encrypter\'s failure is named'   => [self::REDACTION_NOTE, '`Privacy\FieldEncryptionFailedException`'],
            'no previous exception'               => [self::REDACTION_NOTE, 'has no previous exception'],
            'one report per capture'              => [self::REDACTION_NOTE, 'one report per capture'],
            'any other failure fails the write'   => [self::REDACTION_NOTE, 'Any other failure while minimising fails the write'],
            'words joined with no boundary'       => [self::THREAT_MODEL, '`mypassword`'],
            'only joined words are missed'        => [self::THREAT_MODEL, 'Only words joined with no boundary and not listed'],
            'the facade\'s frame'                 => [self::THREAT_MODEL, 'which no attribute can mark'],
            'the setting that keeps arguments'    => [self::THREAT_MODEL, '`zend.exception_ignore_args`'],
            'minimising at capture'               => [self::THREAT_MODEL, 'nothing raw rests in a deferred callback, event or row'],
            'a secret is never un-redacted'       => [self::THREAT_MODEL, 'A built-in secret is never un-redacted'],
            'no key means no field'               => [self::THREAT_MODEL, 'An `ENCRYPT` field with no key is dropped'],
            'what a diagnostic never holds'       => [self::THREAT_MODEL, 'Diagnostics never hold a value or a dynamic key'],
            'the key falls with the application'  => [self::THREAT_MODEL, 'A key from `app.key` falls with it'],
            'a dedicated key'                     => [self::THREAT_MODEL, 'A dedicated `redaction.key` allows independent operation'],
            'failed sign-ins correlate'           => [self::THREAT_MODEL, 'Failed sign-ins correlate with each other'],
            'a pseudonym is never another hash'   => [self::THREAT_MODEL, 'A pseudonym never equals an identifier hash or an IP hash'],
            'a value hashes alike in any field'   => [self::THREAT_MODEL, 'the same value does give the same hash in any field of any code'],
            'a field needing no linkage'          => [self::THREAT_MODEL, 'a field needing no linkage should use `drop` or `encrypt`'],
            'a key change is visible'             => [self::THREAT_MODEL, 'A key change is visible through the fingerprint'],
            'often shipped'                       => [self::THREAT_MODEL, 'often shipped off the server'],
            'what the encryption protects'        => [self::THREAT_MODEL, 'protects a database copy and not a compromised application holding the key'],
            'a spill is not encrypted'            => [self::THREAT_MODEL, 'A spill line is not encrypted'],
            'what a log\'s readers see'           => [self::THREAT_MODEL, 'no `MessageLogged` listener sees a spill line'],
            'other holders of a spill line'       => [self::THREAT_MODEL, 'a spill on the default channel can post a record to a chat room'],
            'what signing establishes'            => [self::THREAT_MODEL, 'What signing establishes'],
            'uncommitted is not evidence'         => [self::OUTCOMES_NOTE, 'A record for an uncommitted operation must not later become committed evidence.'],
            'a bound spill waits'                 => [self::OUTCOMES_NOTE, 'A bound spill waits in memory'],
            'a spill waits for its connection'    => [self::OUTCOMES_NOTE, 'spill waits for any transaction still open on the connection it was written to'],
            'a spill written at once'             => [self::OUTCOMES_NOTE, 'spill is written at once'],
            'evidence of an attempt'              => [self::OUTCOMES_NOTE, 'evidence of an attempt, not of a committed change'],
            'the remaining gap'                   => [self::OUTCOMES_NOTE, 'The gap stays for `after-commit-outbox-other`'],
            'the sync gap'                        => [self::OUTCOMES_NOTE, 'a process that dies between a sync commit and its write loses it'],
            'the one decoder'                     => [self::DELIVERY_NOTE, '`Records\EnvelopeCodec` is the one decoder'],
            'failures move before the commit'     => [self::DELIVERY_NOTE, 'moves finalisation and insert failures before the commit'],
            'the guaranteed format'               => [self::DELIVERY_NOTE, 'Replay is guaranteed only for that format'],
            'at least once'                       => [self::DELIVERY_NOTE, 'at-least-once'],
            'no order'                            => [self::DELIVERY_NOTE, 'Delivery order is not guaranteed'],
            'calls within the lease'              => [self::DELIVERY_NOTE, 'a destination call must finish within `delivery.outbox.lease_seconds`'],
            'clocks within the lease'             => [self::DELIVERY_NOTE, 'worker clocks must agree to well within the lease'],
            'no drain inside a transaction'       => [self::DELIVERY_NOTE, 'the drain refuses to run inside a transaction'],
            'a stack and its capabilities'        => [self::DELIVERY_NOTE, 'joins a transaction only when every destination does'],
            'a host-fatal secondary failure'      => [self::DELIVERY_NOTE, 'a reporter or a listener on any connection with a transaction open propagates sanitised'],
            'nothing is scheduled'                => [self::DELIVERY_NOTE, 'The package does not schedule it'],
            'no job exists'                       => [self::DELIVERY_NOTE, 'because no job exists'],
            'why no job exists'                   => [self::DELIVERY_NOTE, 'Laravel stores exception text in `failed_jobs` separately from the payload'],
            'a call is no proof'                  => [self::DELIVERY_NOTE, 'a successful call to a remote destination is not proof that it ingested the record'],
            'receipts stay'                       => [self::DELIVERY_NOTE, 'Receipts are kept'],
            'old keys stay'                       => [self::DELIVERY_NOTE, 'Old keys must stay in `app.previous_keys`'],
            'a decrypt failure'                   => [self::DELIVERY_NOTE, 'A decrypt failure means a removed key or corruption, and the row is kept'],
            'never signed again'                  => [self::DELIVERY_NOTE, 'never re-signed'],
            'a removed key'                       => [self::DELIVERY_NOTE, 'restore the key or leave the record quarantined'],
            'where third-party evidence goes'     => [self::DELIVERY_NOTE, 'The importer, `audit-log:import`, takes third-party evidence, marked as asserted by its source'],
            'the importer refuses its own'        => [self::DELIVERY_NOTE, 'it refuses this installation\'s own source'],
            'receipts are pruned when terminal'   => [self::DELIVERY_NOTE, 'They are pruned with their entries once terminal'],
            'the drain checks the tombstones'     => [self::DELIVERY_NOTE, 'Every row a drain claims is checked against the tombstones'],
            'a direct store is not refused'       => [self::DELIVERY_NOTE, 'a record an application stores again by hand through `AuditStore::store()` is not refused'],
            'a direct store is resurrected'       => [self::DELIVERY_NOTE, 'Verification reports such a record `resurrected`, so it is detected, not prevented'],
            'export evidence is kept'             => [self::READING_NOTE, self::EXPORT_EVIDENCE],
            'the guide keeps export evidence'     => [self::READING_GUIDE, self::EXPORT_EVIDENCE],
            'a repeated log line'                 => [self::DELIVERY_NOTE, 'a replay can repeat a log destination\'s line'],
            'a rewritten token'                   => [self::DELIVERY_NOTE, 'A `LineFormatter` substitutes `%context%`'],
            'a commit that is really a rollback'  => [self::OUTCOMES_NOTE, 'A commit that is really a rollback writes nothing.'],
            'one record costs no other'           => [self::OUTCOMES_NOTE, 'One record\'s failure costs no other.'],
            'what a callback can still cost'      => [self::OUTCOMES_NOTE, 'An application callback can still cost the audit log its records.'],
            'what counts as fatal'                => [self::OUTCOMES_NOTE, 'What counts as fatal is read from the driver, not from the record.'],
            'a line is a projection'              => [self::DELIVERY_NOTE, 'The log store\'s line is a projection, not the integrity artefact'],
            'access to a spill file'              => [self::DELIVERY_NOTE, '**Access.**'],
            'rotating a spill file'               => [self::DELIVERY_NOTE, '**Rotation.**'],
            'keeping a spill file'                => [self::DELIVERY_NOTE, '**Retention.**'],
            'a percent sign is escaped'           => [self::DELIVERY_NOTE, 'every `%` is written as `\u0025`'],
            'the pinned OCSF version'             => [self::DELIVERY_NOTE, 'OCSF `1.9.0`'],
            'a mapping and its version'           => [self::DELIVERY_NOTE, 'A mapping applies only to records of its definition\'s version'],
            'the fallback'                        => [self::DELIVERY_NOTE, 'falls back to a Base Event'],
            'no invented classification'          => [self::DELIVERY_NOTE, 'A classification is never invented'],
            'the CEF header'                      => [self::DELIVERY_NOTE, 'CEF:0|Sine Macula|laravel-audit-log|<record_version>|<event>|<event>|<severity>|<extension>'],
            'the CEF extension'                   => [self::DELIVERY_NOTE, '`externalId`'],
            'a lost event'                        => [self::EVENT_MODEL, 'A crash between delete and dispatch loses an `AuditRecorded`'],
            'the event holds no value'            => [self::EVENT_MODEL, 'Neither holds a value of the record'],
            'the event contract'                  => [self::EVENT_MODEL, '`Contracts\AuditLogEvent`'],
            'what the guard leaves out'           => [self::EVENT_MODEL, 'The guard does not cover a contributor or an `AuditRecorded` listener'],
            'the failing fake by mode'            => [$testing, 'What the caller sees is the write path\'s, not the fake\'s'],
            'the fake says it can'                => [$testing, 'The fake says it is durable and that it joins a transaction on any connection'],
            'the fake in outbox mode'             => [$testing, 'In outbox mode a record reaches the fake when it is drained'],
            'the two tables'                      => [$storage, '`delivery.deliveries_table` (`audit_log_deliveries` by default) is always on the storage connection'],
            'the outbox\'s connection'            => [$storage, '`delivery.outbox.table` (`audit_log_outbox` by default) is on `delivery.outbox.connection`'],
            'the writer\'s other grants'          => [$storage, 'In outbox mode the writer also needs'],
            'a replay never signs'                => [$integrity, 'A replay verifies and never re-signs'],
            'rebuilding a record'                 => [$record, '`AuditRecord::fromEnvelope()`'],
            'the codec in the record model'       => [$record, '`Records\EnvelopeCodec`, the one decoder'],
            'a queued listener'                   => [self::EVENTS_GUIDE, 'Use a queued listener'],
            'alerting on a failure'               => [self::EVENTS_GUIDE, 'Alert on a failed write'],
            'alerting on a record'                => [self::EVENTS_GUIDE, 'Alert on a stored record'],
            'what a listener may do'              => [self::EVENTS_GUIDE, 'What a listener may do'],
            'the one capture that waits'          => [self::OUTCOMES_NOTE, 'the one captured source that waits for commit'],
            'a capture\'s rule'                   => [self::OUTCOMES_NOTE, 'A capture follows the `report` rule and never reads `failure.mode`'],
            'a capture\'s one escape'             => [self::OUTCOMES_NOTE, '`captured-host-fatal` is the one failure a capture lets out'],
            'a capture never reads the mode'      => [self::DELIVERY_NOTE, 'A capture never reads `failure.mode`'],
            'nothing leaves a deferred capture'   => [self::DELIVERY_NOTE, 'nothing leaves its commit callback'],
            'the bound covers the bundle'         => [self::DELIVERY_NOTE, '`EnvelopeCodec::MAX_BYTES` applies to the whole bundle'],
            'a destination keeping none'          => [self::DELIVERY_NOTE, 'the row is retried, then failed and kept, never deleted'],
            'guards excluded by configuration'    => [self::CAPTURE_GUIDE, 'by configuration and never by detection'],
            'every gate evaluation'               => [self::CAPTURE_GUIDE, 'Every evaluation is recorded'],
            'reason codes are the application\'s' => [self::CAPTURE_GUIDE, 'Treat that list as application-controlled data'],
            'the gate names no guard'             => [self::CAPTURE_GUIDE, 'The Gate names no guard, so the record has none'],
            'raw values'                          => [self::CAPTURE_GUIDE, 'Values are read raw'],
            'two saves'                           => [self::CAPTURE_GUIDE, 'Two saves before a commit give two rows'],
            'one row per restore'                 => [self::CAPTURE_GUIDE, 'A restore and a force delete are one row each'],
            'the members\' key'                   => [self::CAPTURE_GUIDE, 'A rotated key must stay in `app.previous_keys`'],
            'the artifact\'s retention'           => [self::CAPTURE_GUIDE, 'An artifact follows its entry\'s retention'],
            'a mapper writes nothing'             => [self::EXTENDING_GUIDE, 'Its builder has no recorder, and nothing it records is written'],
            'what a mapper sets off'              => [self::EXTENDING_GUIDE, 'What the mapper\'s own work sets off is captured as it would be anywhere else'],
            'a mapper never recurses'             => [self::EXTENDING_GUIDE, 'so a mapper never runs inside itself'],
            'an attachment kept atomically'       => [self::EXTENDING_GUIDE, 'only when it keeps the attachment and its entry atomically'],
            'no detection'                        => [self::EXTENDING_GUIDE, 'The package never looks for another package'],
            'a binding beats a default'           => [self::COMPOSITION_NOTE, 'the other binding always wins'],
            'registration is frozen'              => [self::COMPOSITION_NOTE, 'each is refused with a `\LogicException` once the application has booted'],
            'booting cannot fail on a setting'    => [self::COMPOSITION_NOTE, 'a malformed setting is reported by `audit-log:check`, never by a failed boot'],
        ];

        yield from self::integrityStatements();

        foreach (self::INTEGRITY_LIMITS as $limit) {
            yield 'the threat model: ' . $limit => [self::THREAT_MODEL, $limit];
        }

        foreach (self::ERASURE_LIMITS as $limit) {
            yield 'the threat model on erasure: ' . $limit => [self::THREAT_MODEL, $limit];
        }

        yield from self::operationsStatements();

        yield from self::privacyStatements();
    }

    /**
     * Each note states what it must, however the line is wrapped.
     *
     * @param  string  $note
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideRequiredStatements')]
    public function testEachNoteStatesWhatItMust(string $note, string $statement): void
    {
        self::assertStringContainsString($statement, self::prose($note));
    }

    /**
     * Rows of `[note, extra sections]`: the sections a note has beyond the
     * standard ones, in order.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideExtraSections(): iterable
    {
        yield from [
            'redaction'    => [self::REDACTION_NOTE, ['Key Matching', 'Field Rules', 'Budgets And Omission', 'IP Modes']],
            'threat model' => [
                self::THREAT_MODEL,
                ['Limits Of Key Matching', 'Keys And Brute Force', 'Spill And Outbox', 'Limits Of Integrity', 'Limits Of A PHP Access Policy', 'Limits Of Erasure'],
            ],
            'delivery'  => [self::DELIVERY_NOTE, ['Spill Channel', 'Claims And Receipts', 'Replay', 'Stores And Capabilities', 'Captures And Bundles', 'Formatters']],
            'integrity' => [self::INTEGRITY_NOTE, ['Seals', 'Anchors', 'Verification', 'Pruning And Erasure', 'Alerting And Progress', 'Seams Left']],
            'reading'   => [self::READING_NOTE, ['Seams Left']],
            'privacy'   => [
                self::PRIVACY_NOTE,
                ['Keys', 'Encryption', 'Key Uses', 'Reading', 'Erasure', 'Restores', 'What Is Not Erased', 'Stores And What They Hold', 'Seams Left'],
            ],
        ];
    }

    /**
     * Extra note sections sit in order before the implementation anchors.
     *
     * @param  string  $note
     * @param  list<string>  $extra
     * @return void
     */
    #[DataProvider('provideExtraSections')]
    public function testEachNoteHasItsExtraSectionsInOrder(string $note, array $extra): void
    {
        preg_match_all('/^## (.+)$/m', self::withoutCodeBlocks(self::read($note)), $sections);

        self::assertSame([...array_slice(self::SECTIONS, 0, 4), ...$extra, ...array_slice(self::SECTIONS, 4)], $sections[1]);
    }

    /**
     * The threat model states the limits of key matching with their remedy.
     *
     * @return void
     */
    public function testTheThreatModelStatesTheLimitsOfKeyMatching(): void
    {
        self::assertStringContainsString(self::KEY_MATCHING_LIMITS, self::prose(self::THREAT_MODEL));
    }

    /**
     * The threat model's purpose opens with those limits.
     *
     * @return void
     */
    public function testTheThreatModelOpensWithThoseLimits(): void
    {
        $paragraphs = preg_split('/\n\s*\n/', trim(self::section(self::read(self::THREAT_MODEL), 'Purpose'))) ?: [];

        self::assertStringStartsWith(self::KEY_MATCHING_LIMITS, self::collapsed($paragraphs[0] ?? ''));
    }

    /**
     * The threat model states what a leaked key gives up, in its own section.
     *
     * @return void
     */
    public function testTheThreatModelStatesTheBruteForceLimit(): void
    {
        self::assertStringContainsString(self::BRUTE_FORCE_LIMIT, self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Keys And Brute Force')));
    }

    /**
     * The threat model states each limit of integrity in its own section.
     *
     * @return void
     */
    public function testTheThreatModelStatesEachLimitOfIntegrity(): void
    {
        $section = self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Limits Of Integrity'));

        foreach (self::INTEGRITY_LIMITS as $limit) {
            self::assertStringContainsString($limit, $section, sprintf('The threat model\'s limits of integrity do not say: %s.', $limit));
        }
    }

    /**
     * The threat model states each limit of erasure in its own section.
     *
     * @return void
     */
    public function testTheThreatModelStatesTheLimitsOfErasure(): void
    {
        $section = self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Limits Of Erasure'));

        foreach (self::ERASURE_LIMITS as $limit) {
            self::assertStringContainsString($limit, $section, sprintf('The threat model\'s limits of erasure do not say: %s.', $limit));
        }
    }

    /**
     * The threat model's key matching section names its limits.
     *
     * @return void
     */
    public function testTheThreatModelNamesEachLimitOfKeyMatching(): void
    {
        $section = strtolower(self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Limits Of Key Matching')));

        foreach (['free text', 'innocuous keys', '`mypassword`', 'look-alikes', 'exempt containers', 'notes', '`auditlog::record()`', '`zend.exception_ignore_args`'] as $limit) {
            self::assertStringContainsString($limit, $section);
        }
    }

    /**
     * The redaction note and the threat model call key matching a heuristic,
     * never fail-closed.
     *
     * @return void
     */
    public function testTheRedactionNoteCallsKeyMatchingAHeuristic(): void
    {
        $section = self::section(self::read(self::REDACTION_NOTE), 'Key Matching');

        self::assertStringContainsString('heuristic', $section);
        self::assertSame(0, preg_match(self::FAIL_CLOSED, $section));
        self::assertSame(0, preg_match(self::FAIL_CLOSED, self::read(self::THREAT_MODEL)));
    }

    /**
     * The fail-closed pattern finds each form, across lines, and no look-alike.
     *
     * @return void
     */
    public function testTheFailClosedPatternFindsEachForm(): void
    {
        foreach (['fail-closed', 'Fails closed', "fails\n  closed", 'failing closed', 'failed-closed', 'fail closed'] as $phrase) {
            self::assertSame(1, preg_match(self::FAIL_CLOSED, $phrase), $phrase);
        }

        foreach (['a failure closed it', 'failsafe', 'the door is closed'] as $phrase) {
            self::assertSame(0, preg_match(self::FAIL_CLOSED, $phrase), $phrase);
        }
    }

    /**
     * Rows of `[entry]`: each matcher survivor, exempt final token and
     * sensitive unit.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMatcherEntries(): iterable
    {
        foreach ([...Redactor::SURVIVORS, ...array_map(static fn (string $token): array => [$token], Redactor::EXEMPT_FINAL_TOKENS), ...Redactor::SENSITIVE_UNITS] as $tokens) {

            $entry = implode('_', $tokens);

            yield $entry => [$entry];
        }
    }

    /**
     * Every matcher entry is in the redaction note's key matching section.
     *
     * @param  string  $entry
     * @return void
     */
    #[DataProvider('provideMatcherEntries')]
    public function testTheRedactionNoteListsEveryMatcherEntry(string $entry): void
    {
        self::assertStringContainsString('`' . $entry . '`', self::section(self::read(self::REDACTION_NOTE), 'Key Matching'));
    }

    /**
     * Every IP mode has a row of its own in the redaction note's matrix.
     *
     * @return void
     */
    public function testTheRedactionNoteHasARowForEveryIpMode(): void
    {
        $section = self::section(self::read(self::REDACTION_NOTE), 'IP Modes');

        foreach (IpMode::cases() as $mode) {
            self::assertSame(1, preg_match('/^\| `' . $mode->value . '` +\|/m', $section), sprintf('The matrix has no row for `%s`.', $mode->value));
        }
    }

    /**
     * Every redaction setting's env var is in the README.
     *
     * @return void
     */
    public function testEveryRedactionLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_REDACTION_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertCount(5, $variables[0], 'The configuration does not read the redaction environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
        }
    }

    /**
     * Every failure and delivery setting's env var is in the README.
     *
     * @return void
     */
    public function testEveryDeliveryLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_(?:FAILURE|DELIVERY)_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertCount(9, $variables[0], 'The configuration does not read the failure and delivery environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
        }
    }

    /**
     * Every integrity setting's env var is in the README.
     *
     * @return void
     */
    public function testEveryIntegrityLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_INTEGRITY_(?:LOG|CHECKPOINTS|MEMBERS|STATE|SEAL|VERIFY|ANCHOR)_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertCount(17, $variables[0], 'The configuration does not read the integrity environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
        }
    }

    /**
     * Every integrity status and finding has a row; a finding names its status.
     *
     * @return void
     */
    public function testTheIntegrityNoteHasARowForEveryStatusAndFinding(): void
    {
        $section = self::section(self::read(self::INTEGRITY_NOTE), 'Verification');

        foreach ([...IntegrityStatus::cases(), ...AnchorStatus::cases()] as $status) {
            self::assertSame(1, preg_match('/^\| `' . $status->value . '` +\|/m', $section), sprintf('The integrity note has no row for `%s`.', $status->value));
        }

        foreach (Finding::cases() as $finding) {

            $row = '/^\| `' . $finding->value . '` +\| `' . $finding->status()->value . '` +\|/m';

            self::assertSame(1, preg_match($row, $section), sprintf('The integrity note has no row for `%s` giving `%s`.', $finding->value, $finding->status()->value));
        }
    }

    /**
     * The operations guide opens with its title and has its sections, in order.
     *
     * @return void
     */
    public function testTheOperationsGuideHasItsSections(): void
    {
        $guide = self::withoutCodeBlocks(self::read(self::OPERATIONS_GUIDE));

        preg_match_all('/^## (.+)$/m', $guide, $sections);

        self::assertStringStartsWith("# Operations\n", $guide);
        self::assertSame(self::OPERATIONS_SECTIONS, $sections[1]);
    }

    /**
     * The sealing-at-volume section shows both engines' plans and claims
     * nothing beyond them.
     *
     * @return void
     */
    public function testTheOperationsGuideMakesNoClaimBeyondItsMeasurement(): void
    {
        $section = self::section(self::read(self::OPERATIONS_GUIDE), 'Sealing at volume');
        $prose   = self::collapsed(self::withoutCodeBlocks($section));

        preg_match_all('/^ *```text\n/m', $section, $plans);

        self::assertStringContainsString(self::ONE_MACHINE, $prose);

        foreach (['`EXPLAIN FORMAT=TREE`', '`EXPLAIN (ANALYZE, BUFFERS)`', 'MySQL 8.4', 'PostgreSQL 17', '100,000', '1,000,000'] as $fact) {
            self::assertStringContainsString($fact, $prose);
        }

        self::assertGreaterThanOrEqual(4, count($plans[0]), 'The operations guide does not show a plan of each query on each engine.');
        self::assertSame(0, preg_match(self::BEYOND_MEASUREMENT, $prose), 'The operations guide claims more than its measurements show.');
    }

    /**
     * The beyond-measurement pattern finds each form and no look-alike.
     *
     * @return void
     */
    public function testTheBeyondMeasurementPatternFindsEachForm(): void
    {
        foreach (['it scales', 'Scalable', 'scaling up', 'guaranteed', 'at any size', "any\n  volume", 'unbounded', 'production-ready', "fast\n  enough"] as $claim) {
            self::assertSame(1, preg_match(self::BEYOND_MEASUREMENT, $claim), $claim);
        }

        foreach (['the lookback window', 'a sweep of 1,000,000 entries', 'each run reads', 'a bound', 'any server'] as $text) {
            self::assertSame(0, preg_match(self::BEYOND_MEASUREMENT, $text), $text);
        }
    }

    /**
     * Rows of `[text]`: each integrity command and option, as declared.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIntegrityCommands(): iterable
    {
        foreach ([new SealCommand, new VerifyCommand] as $command) {

            $name = (string) $command->getName();

            yield $name => ['`' . $name . '`'];

            foreach ($command->getDefinition()->getOptions() as $option) {
                yield $name . ' --' . $option->getName() => ['`--' . $option->getName() . '`'];
            }
        }
    }

    /**
     * Each integrity command and option is named in the operations guide.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideIntegrityCommands')]
    public function testEveryCommandIsDocumented(string $text): void
    {
        self::assertStringContainsString($text, self::read(self::OPERATIONS_GUIDE), sprintf('The operations guide does not name %s.', $text));
    }

    /**
     * The rows are what the commands declare, so the check is not empty.
     *
     * @return void
     */
    public function testTheCommandRowsAreEveryDeclaredOption(): void
    {
        $rows = array_map(static fn (array $row): string => $row[0], iterator_to_array(self::provideIntegrityCommands()));

        self::assertSame(['`audit-log:seal`', '`--sweep`', '`audit-log:verify`', '`--from`', '`--to`', '`--json`', '`--strict`', '`--sweep-first`'], array_values($rows));
    }

    /**
     * Each progress name is in the monitoring section, with what stale means.
     *
     * @return void
     */
    public function testTheOperationsGuideNamesEveryProgressName(): void
    {
        $names   = array_values(array_filter((new \ReflectionClass(IntegrityProgress::class))->getConstants(\ReflectionClassConstant::IS_PUBLIC), is_string(...)));
        $section = self::section(self::read(self::OPERATIONS_GUIDE), 'Monitor');

        self::assertCount(9, $names, 'The progress names are not the ones the guide was written for.');

        foreach ($names as $name) {
            self::assertStringContainsString('`' . $name . '`', $section, sprintf('The operations guide does not name the progress `%s`.', $name));
        }
    }

    /**
     * No document says a failed record is not true.
     *
     * @return void
     */
    public function testNoNoteSaysAFailedRecordIsNotTrue(): void
    {
        self::assertSame(0, preg_match(self::NOT_TRUE, self::documentation()), 'A document says a failed record is not true.');
    }

    /**
     * The not-true pattern finds each form, across lines, and no look-alike.
     *
     * @return void
     */
    public function testTheNotTruePatternFindsEachForm(): void
    {
        foreach (['the record is not true', 'The record is not true', "the record\n  is not true", 'a failed record was never true', 'the spilled record is not true'] as $phrase) {
            self::assertSame(1, preg_match(self::NOT_TRUE, $phrase), $phrase);
        }

        foreach (['the record is true', 'A failure or a denial can be true', 'a record is not trusted'] as $phrase) {
            self::assertSame(0, preg_match(self::NOT_TRUE, $phrase), $phrase);
        }
    }

    /**
     * The outcomes note's guarantees have exactly their rows, in order.
     *
     * @return void
     */
    public function testTheOutcomesTableHasEachRow(): void
    {
        preg_match_all('/^\| `([a-z-]+)` +\|/m', self::section(self::read(self::OUTCOMES_NOTE), 'Guarantees'), $rows);

        self::assertSame(self::OUTCOME_ROWS, $rows[1]);
    }

    /**
     * The automatic-capture guide has its title and sections, in order.
     *
     * @return void
     */
    public function testTheCaptureGuideHasItsSections(): void
    {
        $guide = self::withoutCodeBlocks(self::read(self::CAPTURE_GUIDE));

        preg_match_all('/^## (.+)$/m', $guide, $sections);

        self::assertStringStartsWith("# Automatic capture\n", $guide);
        self::assertSame(self::CAPTURE_SECTIONS, $sections[1]);
    }

    /**
     * The extending guide opens with its title and has its sections, in order.
     *
     * @return void
     */
    public function testTheExtendingGuideHasItsSections(): void
    {
        $guide = self::withoutCodeBlocks(self::read(self::EXTENDING_GUIDE));

        preg_match_all('/^## (.+)$/m', $guide, $sections);

        self::assertStringStartsWith("# Extending\n", $guide);
        self::assertSame(self::EXTENDING_SECTIONS, $sections[1]);
    }

    /**
     * Every public contract an integration implements has an extensibility row.
     *
     * @return void
     */
    public function testEveryPublicContractIsAnExtensionPoint(): void
    {
        $guide   = self::read(self::EXTENDING_GUIDE);
        $start   = (int) strpos($guide, '## Extensibility');
        $section = substr($guide, $start, (int) strpos($guide, '## Mapping another package\'s events') - $start);
        $missing = [];

        foreach (glob(dirname(__DIR__, 3) . '/src/Contracts/*.php') ?: [] as $file) {
            $name = basename($file, '.php');

            if ($name === 'AuditLogEvent' || !str_contains((string) file_get_contents($file), "\n * @api\n")) {
                continue;
            }

            if (preg_match('/^\| [^|]+\| [^\n]*`Contracts\\\\' . $name . '`/m', $section)) {
                continue;
            }

            $missing[] = $name;
        }

        self::assertSame([], $missing, 'Every public contract has a row of the extensibility table.');
    }

    /**
     * Rows of `[section, statement]`: each gap in capture.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideCaptureGaps(): iterable
    {
        yield from self::CAPTURE_GAPS;
    }

    /**
     * Each gap in capture is stated in its section of the capture guide.
     *
     * @param  string  $section
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideCaptureGaps')]
    public function testEveryCaptureGapIsDocumented(string $section, string $statement): void
    {
        $text = self::collapsed(self::section(self::read(self::CAPTURE_GUIDE), $section));

        self::assertNotSame('', $text, sprintf('The automatic-capture guide has no section %s.', $section));
        self::assertStringContainsString($statement, $text, sprintf('The automatic-capture guide\'s section %s does not say: %s.', $section, $statement));
    }

    /**
     * Every capture setting's env var is in the README and the capture guide.
     *
     * @return void
     */
    public function testEveryCaptureLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_CAPTURE_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertCount(4, $variables[0], 'The configuration does not read the capture environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
            self::assertStringContainsString('`' . $variable . '`', self::read(self::CAPTURE_GUIDE));
        }
    }

    /**
     * The documented correlation id format is the one the builder enforces.
     *
     * @return void
     */
    public function testTheExtendingGuideDocumentsTheCorrelationFormat(): void
    {
        $section = self::collapsed(self::section(self::read(self::EXTENDING_GUIDE), 'Correlation ids'));

        self::assertStringContainsString(self::CORRELATION_FORMAT, $section);
        self::assertStringContainsString('`app:ticket-123`', $section);
        self::assertStringContainsString('a lower-case namespace of up to 32 characters', $section);

        foreach (['app:ticket-123', str_repeat('a', 32) . ':1'] as $accepted) {
            $pending = new PendingRecord;

            self::assertSame($pending, $pending->correlatedWith($accepted), $accepted);
        }

        foreach ([str_repeat('a', 33) . ':1', 'App:ticket-123', 'ticket-123'] as $refused) {
            try {
                (new PendingRecord)->correlatedWith($refused);

                self::fail(sprintf('Expected `%s` to be refused.', $refused));
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('`<namespace>:<value>`', $exception->getMessage());
            }
        }
    }

    /**
     * Segments a watched model may not use are the reserved prefixes, in order.
     *
     * @return void
     */
    public function testTheReservedSegmentsAreTheVocabularysPrefixes(): void
    {
        self::assertSame(self::RESERVED_PREFIXES, array_map(static fn (string $segment): string => $segment . '.', ModelWatch::RESERVED_SEGMENTS));
    }

    /**
     * The capture guide names every captured code and every watched-model code.
     *
     * @return void
     */
    public function testTheCaptureGuideNamesEveryPackageCode(): void
    {
        $guide = self::read(self::CAPTURE_GUIDE);
        $codes = [
            ...array_map(static fn (CapturedActivity $activity): string => $activity->value, CapturedActivity::cases()),
            ...array_map(static fn (ModelEvent $change): string => $change->codeFor('{as}'), ModelEvent::cases()),
        ];

        self::assertCount(16, $codes);

        foreach ($codes as $code) {
            self::assertStringContainsString('`' . $code . '`', $guide, sprintf('The automatic-capture guide does not name `%s`.', $code));
        }
    }

    /**
     * The documented spill channel matches the tested one, key for key.
     *
     * @return void
     */
    public function testTheDocumentedChannelIsTheTestedOne(): void
    {
        $block  = self::documentedChannel(self::section(self::read(self::DELIVERY_NOTE), 'Spill Channel'));
        $tested = DocumentedSpillChannel::config('');

        preg_match_all('/^ +\'(\w+)\' +=>/m', $block, $keys);

        self::assertSame(array_keys($tested), $keys[1], 'The documented channel does not have the keys of the tested one.');

        unset($tested['path']);

        foreach ($tested as $key => $value) {
            self::assertStringContainsString(self::channelEntry($key, $value), self::collapsed($block));
        }
    }

    /**
     * A channel entry is written as it is in configuration.
     *
     * @return void
     */
    public function testAChannelEntryIsWrittenAsItIsInConfiguration(): void
    {
        self::assertSame('\'level\' => \'critical\'', self::channelEntry('level', 'critical'));
        self::assertSame('\'permission\' => 0600', self::channelEntry('permission', 0600));
        self::assertSame('\'formatter\' => Tests\Unit\Documentation\DocumentationTest::class', self::channelEntry('formatter', self::class));
        self::assertSame('\'with\' => [\'format\' => "%message%\n", \'inline\' => false]', self::channelEntry('with', ['format' => "%message%\n", 'inline' => false]));
    }

    /**
     * The channel block is found by name; a section without it gives nothing.
     *
     * @return void
     */
    public function testTheChannelBlockIsFoundByItsName(): void
    {
        $section = "Text.\n\n```php\n\$other = 1;\n```\n\n```php\n'audit-spill' => [\n    'driver' => 'single',\n],\n```\n";

        self::assertSame("'audit-spill' => [\n    'driver' => 'single',\n],\n", self::documentedChannel($section));
        self::assertSame('', self::documentedChannel("```php\n\$other = 1;\n```\n"));
    }

    /**
     * The threat model and the delivery note call the spill and the outbox
     * personal data.
     *
     * @return void
     */
    public function testTheSpillAndOutboxArePersonalData(): void
    {
        $section = self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Spill And Outbox'));

        self::assertStringContainsString(self::PERSONAL_DATA, $section);
        self::assertStringContainsString('often shipped off the server', $section);
        self::assertStringContainsString('not a compromised application holding the key', $section);
        self::assertStringContainsString('A spill line is not encrypted', $section);
        self::assertStringContainsString('no `MessageLogged` listener', $section);

        self::assertStringContainsString(self::PERSONAL_DATA, self::prose(self::DELIVERY_NOTE));
    }

    /**
     * Every dispatched event has a row in the events guide.
     *
     * @param  string  $class
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEveryEventIsInTheEventsGuide(string $class): void
    {
        self::assertTrue(self::hasEventRow(self::read(self::EVENTS_GUIDE), $class), sprintf('The events guide has no row for %s.', $class));
    }

    /**
     * No document cites a milestone, a release transition or a sibling package.
     *
     * @return void
     */
    public function testNoDocumentCitesAMilestoneATransitionOrASibling(): void
    {
        self::assertSame(0, preg_match(self::MILESTONE, self::documentation()), 'The documentation cites a milestone.');
        self::assertSame(0, preg_match(self::TRANSITION, self::documentation()), 'The documentation describes a transition from a release.');
        self::assertSame(0, preg_match(self::SIBLING, self::documentation()), 'The documentation names another package of the suite.');
    }

    /**
     * The patterns find each form, not the package's name or a look-alike.
     *
     * @return void
     */
    public function testTheMilestoneTransitionAndSiblingPatternsFindEachForm(): void
    {
        foreach (['the milestone', 'in M5', 'M1 to M4'] as $citation) {
            self::assertSame(1, preg_match(self::MILESTONE, $citation), $citation);
        }

        foreach (['A breaking change', 'deprecated', 'Deprecation', 'upgrade notes', 'backward compatible', 'backwards-compatibility'] as $phrase) {
            self::assertSame(1, preg_match(self::TRANSITION, $phrase), $phrase);
        }

        foreach (['sinemacula/laravel-mfa', 'laravel-authentication', 'LARAVEL-IAM'] as $name) {
            self::assertSame(1, preg_match(self::SIBLING, $name), $name);
        }

        foreach (['M0', 'HMAC5', 'a line break', 'upgrade', 'sinemacula/laravel-audit-log'] as $text) {
            self::assertSame(0, preg_match(self::MILESTONE, $text), $text);
            self::assertSame(0, preg_match(self::TRANSITION, $text), $text);
            self::assertSame(0, preg_match(self::SIBLING, $text), $text);
        }
    }

    /**
     * Every file a note's anchors name exists, and every note names one.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('provideCitingNotes')]
    public function testEveryAnchoredFileExists(string $note): void
    {
        $anchored = self::anchoredFiles(self::section(self::read('/docs/design/' . $note), 'Implementation Anchors'));
        $missing  = array_values(array_filter($anchored, static fn (string $file): bool => !is_file(self::root() . '/' . $file)));

        self::assertNotSame([], $anchored, sprintf('%s anchors no file.', $note));
        self::assertSame([], $missing, sprintf('%s anchors files that do not exist.', $note));
    }

    /**
     * The anchor scanner finds each backticked file and no method or constant.
     *
     * @return void
     */
    public function testTheAnchorScannerFindsOnlyFiles(): void
    {
        $section = "- `src/Recorder.php`: `write()`; `config/audit-log.php`: `redaction`.\n- `database/migrations/one.php`, `MARKER`, `Privacy\\Redactor`.\n";

        self::assertSame(['src/Recorder.php', 'config/audit-log.php', 'database/migrations/one.php'], self::anchoredFiles($section));
    }

    /**
     * No document cites a file kept out of the repository.
     *
     * @return void
     */
    public function testNoDocumentCitesAFileKeptOutOfTheRepository(): void
    {
        self::assertSame(0, preg_match(self::LOCAL_ONLY, self::documentation()), 'The documentation cites a file kept out of the repository.');
    }

    /**
     * The local-citation pattern finds each form, not env vars or look-alikes.
     *
     * @return void
     */
    public function testTheLocalCitationPatternFindsEachForm(): void
    {
        foreach (['see FEATURES.md', 'BACKLOG.md', 'AUDIT-REDACT.8', 'BL-33', '.sinemacula/build', 'm4-design.md', 'section §9'] as $citation) {
            self::assertSame(1, preg_match(self::LOCAL_ONLY, $citation), $citation);
        }

        foreach (['AUDIT_LOG_REDACTION_KEY', 'audit-log:check', 'BL-', 'sinemacula/laravel-audit-log'] as $text) {
            self::assertSame(0, preg_match(self::LOCAL_ONLY, $text), $text);
        }
    }

    /**
     * The reading guide opens with its title and has its sections, in order.
     *
     * @return void
     */
    public function testTheReadingGuideHasItsSections(): void
    {
        $guide = self::withoutCodeBlocks(self::read(self::READING_GUIDE));

        preg_match_all('/^## (.+)$/m', $guide, $sections);

        self::assertStringStartsWith("# Reading\n", $guide);
        self::assertSame(self::READING_SECTIONS, $sections[1]);
    }

    /**
     * Rows of `[statement]`: each rule of reading the reading guide must state.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReadingStatements(): iterable
    {
        foreach (self::READING_STATEMENTS as $about => $statement) {
            yield $about => [$statement];
        }
    }

    /**
     * The reading guide makes each of those statements, however wrapped.
     *
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideReadingStatements')]
    public function testEachReadingStatementIsMade(string $statement): void
    {
        self::assertStringContainsString($statement, self::prose(self::READING_GUIDE));
    }

    /**
     * The reading guide's scopes, verification and subject access sections say
     * what they must.
     *
     * @return void
     */
    public function testTheReadingGuidesSectionsSayWhatTheyMust(): void
    {
        $guide        = self::read(self::READING_GUIDE);
        $scopes       = self::collapsed(self::section($guide, 'Scopes'));
        $verification = self::collapsed(self::section($guide, 'Verifying an export'));
        $procedure    = self::collapsed(self::section($guide, 'Answering a subject access request'));

        self::assertStringContainsString('Narrow a scope only through its instance methods', $scopes);
        self::assertStringContainsString('A static factory reached through an instance starts a fresh scope', $scopes);
        self::assertStringContainsString('The verifying viewer\'s scope must reach the export entry: the category `audit`, and the exporter\'s single tenant', $verification);

        foreach (['`file_sha256`', '`membership_sha256`', '`properties._audit.manifest`', 'Whoever holds the key recomputes the entry\'s HMAC'] as $step) {
            self::assertStringContainsString($step, $verification);
        }

        foreach (['<!-- procedure:policy -->', '<!-- procedure:select -->', '<!-- procedure:review -->', '<!-- procedure:erase -->'] as $marker) {
            self::assertSame(1, substr_count($procedure, $marker), sprintf('The procedure does not hold %s once.', $marker));
        }

        foreach (self::PROCEDURE_STATEMENTS as $statement) {
            self::assertStringContainsString($statement, $procedure);
        }

        self::assertStringNotContainsString('the erasure feature\'s', $procedure);
        self::assertStringNotContainsString('erases nothing', $procedure);
    }

    /**
     * The reading guide names every read path value, in code type.
     *
     * @return void
     */
    public function testTheReadingGuideNamesEveryReadValue(): void
    {
        $guide   = self::read(self::READING_GUIDE);
        $missing = [];

        foreach ([ReadPurpose::class, FieldState::class, ExportFormat::class, ExportFinding::class, Acknowledgement::class] as $enum) {
            foreach ($enum::cases() as $case) {
                if (str_contains($guide, '`' . $case->value . '`')) {
                    continue;
                }

                $missing[] = $enum . '::' . $case->name;
            }
        }

        self::assertSame([], $missing, 'The reading guide does not name every value of the read path.');
    }

    /**
     * Every call the reading guide's examples make exists.
     *
     * @return void
     */
    public function testEveryCallTheReadingGuideShowsExists(): void
    {
        preg_match_all('/^ *```php\n(.*?)^ *```[ \t]*$/ms', self::read(self::READING_GUIDE), $blocks);
        preg_match_all('/(?:->|\?->|::)\s*([a-zA-Z_]\w*)\s*\(/', implode("\n", $blocks[1]), $calls);

        $unknown = [];

        foreach (array_values(array_unique($calls[1])) as $call) {

            if (in_array($call, self::APPLICATION_CALLS, true) || self::isDeclaredByAReadingClass($call)) {
                continue;
            }

            $unknown[] = $call;
        }

        self::assertNotSame([], $calls[1], 'The reading guide shows no call.');
        self::assertSame([], $unknown, 'The reading guide shows calls that do not exist.');
    }

    /**
     * The reading call check knows real methods only, so it is not empty.
     *
     * @return void
     */
    public function testTheReadingCallCheckKnowsOnlyRealMethods(): void
    {
        $calls = ['cursorPaginate', 'onlyAbout', 'tenants', 'hasMore', 'describe', 'isVerified', 'assertAudited', 'instance', 'trail'];

        foreach ([...$calls, 'holdingDataOf', 'revealingEncryptedFields', 'lifecycle', 'erase'] as $call) {
            self::assertTrue(self::isDeclaredByAReadingClass($call), $call);
        }

        foreach (['permitted', 'paginate', 'onlyTenants', 'total'] as $call) {
            self::assertFalse(self::isDeclaredByAReadingClass($call), $call);
        }
    }

    /**
     * Rows of `[statement]`: what a PHP access policy cannot do.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePhpPolicyLimits(): iterable
    {
        foreach (self::PHP_POLICY_LIMITS as $about => $statement) {
            yield $about => [$statement];
        }
    }

    /**
     * The threat model states each of those limits in its own section.
     *
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('providePhpPolicyLimits')]
    public function testTheThreatModelStatesTheLimitsOfAPhpPolicy(string $statement): void
    {
        self::assertStringContainsString($statement, self::collapsed(self::section(self::read(self::THREAT_MODEL), 'Limits Of A PHP Access Policy')));
    }

    /**
     * Rows of `[text]`: the export command and each option, as declared.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideExportOptions(): iterable
    {
        $command = new ExportCommand;
        $name    = (string) $command->getName();

        yield $name => ['`' . $name . '`'];

        foreach ($command->getDefinition()->getOptions() as $option) {
            yield $name . ' --' . $option->getName() => ['`--' . $option->getName() . '`'];
        }
    }

    /**
     * The export command and each option are named in the reading guide.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideExportOptions')]
    public function testEveryExportOptionIsDocumented(string $text): void
    {
        self::assertStringContainsString($text, self::read(self::READING_GUIDE), sprintf('The reading guide does not name %s.', $text));
    }

    /**
     * The export rows are what the command declares, so the check is not empty.
     *
     * @return void
     */
    public function testTheExportRowsAreEveryDeclaredOption(): void
    {
        $rows = array_map(static fn (array $row): string => $row[0], iterator_to_array(self::provideExportOptions()));

        self::assertSame(['`audit-log:export`', '`--viewer-type`', '`--viewer-id`', '`--format`', '`--force`', '`--verify`'], array_values($rows));
    }

    /**
     * Every read and export setting's env var is in the README and the guide.
     *
     * @return void
     */
    public function testEveryReadLeafNamesItsEnvVarInTheReadme(): void
    {
        preg_match_all('/\bAUDIT_LOG_(?:READ|EXPORT)_[A-Z_]+\b/', self::read('/config/audit-log.php'), $variables);

        self::assertSame(['AUDIT_LOG_READ_MAX_PER_PAGE', 'AUDIT_LOG_EXPORT_CHUNK'], $variables[0], 'The configuration does not read the read environment variables it should.');

        foreach ($variables[0] as $variable) {
            self::assertStringContainsString('`' . $variable . '`', self::read('/README.md'));
            self::assertStringContainsString('`' . $variable . '`', self::read(self::READING_GUIDE));
        }
    }

    /**
     * No document puts an immediate write outside the caller's transaction.
     *
     * @return void
     */
    public function testNoDocumentSaysTheImmediatePathIsOutsideTheCallersTransaction(): void
    {
        self::assertSame(0, preg_match(self::OUTSIDE_THE_CALLER, self::documentation()), 'A document says the immediate path is outside the caller\'s transaction.');
    }

    /**
     * The outside-the-caller pattern finds each form and no look-alike.
     *
     * @return void
     */
    public function testTheOutsideTheCallerPatternFindsEachForm(): void
    {
        $forms = ['outside the caller\'s transaction', "Outside the\n  caller's transaction", 'outside of the callers transactions', 'outside any caller’s transaction'];

        foreach ($forms as $phrase) {
            self::assertSame(1, preg_match(self::OUTSIDE_THE_CALLER, $phrase), $phrase);
        }

        foreach (['what the caller\'s transaction is left as', 'outside the read guard', 'inside the caller\'s transaction'] as $phrase) {
            self::assertSame(0, preg_match(self::OUTSIDE_THE_CALLER, $phrase), $phrase);
        }
    }

    /**
     * The reading note's seams name what the read path leaves, none that ships.
     *
     * @return void
     */
    public function testTheReadingNoteNamesTheSeamsLeft(): void
    {
        $section = self::collapsed(self::section(self::read(self::READING_NOTE), 'Seams Left'));

        foreach (self::READING_SEAMS as $seam) {
            self::assertStringContainsString($seam, $section, sprintf('The reading note\'s seams do not say: %s.', $seam));
        }

        foreach (self::SHIPPED_SEAMS as $shipped) {
            self::assertStringNotContainsString($shipped, $section, sprintf('The reading note still leaves what ships: %s.', $shipped));
        }
    }

    /**
     * Rows of `[activity]`: every code the read path records.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity}>
     */
    public static function providePackageActivities(): iterable
    {
        foreach (PackageActivity::cases() as $activity) {
            yield $activity->value => [$activity];
        }
    }

    /**
     * Each read path code's vocabulary row lists exactly what it retains.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @return void
     */
    #[DataProvider('providePackageActivities')]
    public function testEachPackageCodesRowKeepsItsDefinitionsProperties(PackageActivity $activity): void
    {
        $section = self::section(self::read('/docs/design/vocabulary.md'), 'Package Codes');
        $row     = '/^\| `' . preg_quote($activity->value, '/') . '` +\|(?:[^|\n]*\|){4}([^|\n]*)\|$/m';

        self::assertSame(1, preg_match($row, $section, $matches), sprintf('The vocabulary has no row for `%s`.', $activity->value));

        preg_match_all('/`([a-z][a-z0-9_]*)`/', $matches[1], $properties);

        $documented = EventDefinition::permissive(EventCode::package($activity))
            ->unlisted(FieldHandling::DROP)
            ->category('audit')
            ->retain(...$properties[1]);

        self::assertNotSame([], $properties[1]);
        self::assertTrue($documented->equals($activity->definition()), sprintf('The vocabulary\'s row for `%s` does not keep what its definition retains.', $activity->value));
    }

    /**
     * Rows of `[note, statement]`: the rules the integrity note must state.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    private static function integrityStatements(): array
    {
        $note = self::INTEGRITY_NOTE;

        return [
            'membership is sealed'        => [$note, 'Membership, not ordering, is what is sealed'],
            'recording is unchanged'      => [$note, 'no application-level lock or inline chain is added to recording'],
            'the settle delay'            => [$note, 'The settle delay is an operational delay, not a correctness mechanism'],
            'no savepoint retry'          => [$note, 'A savepoint retry is never used'],
            'the chain'                   => [$note, 'The chain is over seal digests'],
            'the historical key'          => [$note, 'Verification selects the historical key by the stored id, never the current key'],
            'no reused key id'            => [$note, 'a key id is never reused for different material'],
            'the key lifetimes'           => [$note, 'separate lifetimes for encryption keys, row-HMAC keys and seal-verification keys'],
            'an idempotent anchor'        => [$note, 'Anchoring the same seal again returns the same receipt'],
            'the receipt is a cache'      => [$note, 'The receipt columns are a cache, never the authority'],
            'an empty remote'             => [$note, 'An empty remote with a non-empty local log is `unanchored`'],
            'pruning excuses nothing'     => [$note, 'Pruning never excuses a bad signature, a broken chain or an anchor contradiction'],
            'a ranged run'                => [$note, 'A ranged run never establishes the integrity of the whole log'],
            'object lock'                 => [$note, self::OBJECT_LOCK],
            'a new version'               => [$note, self::NEW_VERSION],
            'conditional guarantees'      => [$note, 'These guarantees are conditional on that configuration'],
            'a writable disk'             => [$note, 'A disk the application can overwrite or delete is no anchor'],
            'the anchoring grace'         => [$note, 'A seal sealed within 15 minutes of a strict run\'s start does not fail it while it waits for its anchoring'],
            'no repair'                   => [$note, 'Verification never repairs and never re-signs'],
            'the seal key'                => [$note, '`hash_hkdf(\'sha256\', $secret, 32, \'sinemacula/audit-log:seal:v1\', \'\')`'],
            'the derivation\'s info'      => [$note, 'the info `sinemacula/audit-log:seal:v1`'],
            'the derivation\'s salt'      => [$note, 'an empty salt'],
            'the derivation\'s length'    => [$note, 'a length of 32 bytes'],
            'the seal label'              => [$note, 'the label `audit-log:seal:v1`, a line feed and the 64 hex characters of the seal digest'],
            'the prune label'             => [$note, 'the label `audit-log:prune:v2`, a line feed'],
            'the bitmap'                  => [$note, 'bit `i % 8` of byte `i / 8`'],
            'the digest\'s encoding'      => [$note, 'the lower-case hex SHA-256 of the canonical encoding of the envelope'],
            'the members digest\'s order' => [$note, 'sorted bytewise by `entry_id`'],
            'the golden vectors'          => [$note, '`tests/Fixtures/Integrity/seal-v1.json`'],
            'the journal commitment'      => [$note, 'Every seal commits to the lifecycle journal\'s head'],
            'the resurrected finding'     => [$note, 'A member a valid record covers that is present is `resurrected`'],
            'pruning is per entry'        => [$note, 'per entry and never per segment'],
            'the journal label'           => [$note, 'the label `audit-log:lifecycle:<kind>:v1`, a line feed'],
            'the journal derivation'      => [$note, '`hash_hkdf(\'sha256\', $secret, 32, \'sinemacula/audit-log:lifecycle:v1\', \'\')`'],
            'the ledger is always asked'  => [$note, 'even one with no member missing'],
            'the prune is conditional'    => [$note, 'The prune is registered only when it can delete something'],
        ];
    }

    /**
     * Rows of `[note, statement]`: the owners' keys rules each note states.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    private static function privacyStatements(): array
    {
        $record      = '/docs/design/record-model.md';
        $definitions = '/docs/design/event-definitions.md';
        $storage     = '/docs/design/storage.md';

        return [
            'a fingerprint falls to brute force'  => [self::THREAT_MODEL, 'so it falls to brute force like any identifier once the integrity key leaks'],
            'a leak gives wrapped keys'           => [self::THREAT_MODEL, 'the owners\' wrapped keys, but neither a wrapping key, a hashing key nor plaintext'],
            'erasure keeps verification'          => [self::INTEGRITY_NOTE, 'an erasure keeps verification whole'],
            'the key store section'               => [self::INTEGRITY_NOTE, 'A complete run then verifies the owners\' key store'],
            'a missing key use'                   => [self::INTEGRITY_NOTE, 'a missing key use hides the entry from its owner\'s erasure'],
            'no destroyed set'                    => [self::INTEGRITY_NOTE, 'No set of destroyed keys is kept'],
            'the grant never asks without'        => [self::READING_NOTE, 'A scope without the grant never asks a reader'],
            'only from a verified row'            => [self::READING_NOTE, '`Privacy\EncryptedField`, from a verified row'],
            'a page in one call'                  => [self::READING_NOTE, 'in one call, answered in order and in number'],
            'the owner\'s entries'                => [self::READING_NOTE, '`holdingDataOf()` compiles to an `EXISTS` over the key uses joined to the owner\'s keys'],
            'key uses with their entry'           => [$storage, 'so a failed key use rolls its entry back and neither is ever kept without the other'],
            'no envelope keeps one insert'        => [$storage, 'A record with no such envelope keeps its single insert'],
            'the default encrypter'               => [self::REDACTION_NOTE, 'The package binds `Privacy\SubjectKeyEncrypter`, the default encrypter'],
            'never encrypting is explicit'        => [self::REDACTION_NOTE, 'is the explicit choice never to encrypt'],
            'typed plaintext'                     => [self::REDACTION_NOTE, 'so the string `"true"` and the boolean `true` seal apart'],
            'no reason discloses an erasure'      => [self::REDACTION_NOTE, 'an owner with no key, an absent owner and an erased owner read alike'],
            'a record is personal data'           => [$record, 'A record is personal data about everyone it names'],
            'only a sealed value is erased'       => [$record, 'Only a value sealed under an owner\'s key is erased, by destroying the key'],
            'an encrypted address is erased'      => [$record, 'unless the `encrypt` IP mode sealed it under the actor\'s key, in which case it is erased with that key'],
            'encryption by default'               => [$definitions, 'the package\'s encrypter seals each such field under a key of its owner\'s by default'],
            'categories are erasable apart'       => [$definitions, 'leaves the owner\'s other categories erasable'],
            'key uses at the drain'               => [self::DELIVERY_NOTE, 'writes its key uses with its entry, at the drain or the replay'],
            'a hold protects only stored records' => [self::DELIVERY_NOTE, 'a hold protects a record only once it is stored'],
            'a late delivery is erased'           => [self::DELIVERY_NOTE, 'its owner\'s fields read `erased` by construction'],
            'pending deliveries refuse'           => [self::DELIVERY_NOTE, 'an erasure refuses while the outbox holds rows created before the erasure started'],
        ];
    }

    /**
     * Rows of `[guide, statement]`: the integrity commands' caveats to state.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    private static function operationsStatements(): array
    {
        $guide = self::OPERATIONS_GUIDE;

        return [
            'a missed run'               => [$guide, 'a missed scheduled run raises nothing'],
            'one machine'                => [$guide, self::ONE_MACHINE],
            'the lookback reads'         => [$guide, 'the recent pass reads the whole lookback window every run'],
            'the lookback trades'        => [$guide, 'the lookback trades latency against cost'],
            'the clock skew'             => [$guide, 'The lookback must exceed the worst clock skew between the servers that record'],
            'sqlite in wal'              => [$guide, 'On SQLite use WAL: in rollback-journal mode a sealer\'s read blocks every writer\'s commit until its transaction ends'],
            'discovery probes'           => [$guide, 'about two existence checks per doubling of the log'],
            'the head settles'           => [$guide, 'the head settles every seal\'s anchoring with no further request'],
            'bounded timeouts'           => [$guide, 'The anchor disk must have bounded timeouts'],
            'in the background'          => [$guide, '`runInBackground()`'],
            'a stale lock'               => [$guide, '`php artisan schedule:clear-cache`'],
            'replayed records'           => [$guide, 'The scheduled verification sweeps first'],
            'the guide\'s object lock'   => [$guide, self::OBJECT_LOCK],
            'the guide\'s new version'   => [$guide, self::NEW_VERSION],
            'the guide\'s conditions'    => [$guide, 'These guarantees are conditional on that configuration'],
            'no sdk'                     => [$guide, 'no S3 SDK dependency'],
            'without overlapping'        => [$guide, '`withoutOverlapping()`'],
            'on one server'              => [$guide, '`onOneServer()`'],
            'the grants'                 => [$guide, 'Grants And Triggers'],
            'the alert'                  => [$guide, '`IntegrityCheckFailed`'],
            'the guide\'s key lifetimes' => [$guide, 'a key id is never reused for different material'],
            'the guide\'s compliance'    => [$guide, 'Installing the package is not compliance'],
            'four runs'                  => [$guide, 'The package registers four runs on Laravel\'s scheduler'],
            'the prune\'s condition'     => [$guide, 'The prune is registered only when it can delete something'],
            'the export key'             => [$guide, 'Export artifacts need `app.key` kept, or listed in `app.previous_keys`, for as long as their verification is promised.'],
            'the journal\'s key'         => [$guide, 'As long as the journal, which nothing prunes'],
        ];
    }

    /**
     * The configuration's leaf paths, lists and empty arrays included.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leafKeys(array $config, string $prefix = ''): array
    {
        $keys = [];

        foreach ($config as $key => $value) {

            $path = $prefix . $key;

            if (!is_array($value) || $value === [] || array_is_list($value)) {
                $keys[] = $path;

                continue;
            }

            array_push($keys, ...self::leafKeys($value, $path . '.'));
        }

        return $keys;
    }

    /**
     * The keys the text does not name by full path in code type, in order.
     *
     * @param  list<string>  $keys
     * @param  string  $text
     * @return list<string>
     */
    private static function undocumentedKeys(array $keys, string $text): array
    {
        return array_values(array_filter($keys, static fn (string $key): bool => !str_contains($text, '`' . $key . '`')));
    }

    /**
     * Whether a reading guide class, traits included, declares the method.
     *
     * @param  string  $method
     * @return bool
     */
    private static function isDeclaredByAReadingClass(string $method): bool
    {
        foreach (self::READING_CLASSES as $class) {
            if (method_exists($class, $method)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The design notes in docs/design, by file name, the index excluded.
     *
     * @return list<string>
     */
    private static function noteFiles(): array
    {
        $files = array_map(static fn (string $file): string => basename($file), glob(self::root() . '/docs/design/*.md') ?: []);

        return array_values(array_filter($files, static fn (string $file): bool => $file !== 'README.md'));
    }

    /**
     * Whether a heading is in Title Case, short words excepted.
     *
     * @param  string  $title
     * @return bool
     */
    private static function isTitleCase(string $title): bool
    {
        $minor = ['a', 'an', 'and', 'as', 'at', 'by', 'for', 'in', 'of', 'on', 'or', 'the', 'to', 'with'];
        $words = preg_split('/[\s\/-]+/', $title) ?: [];

        foreach ($words as $position => $word) {
            if (preg_match('/\A\p{Lu}/u', $word) !== 1 && ($position === 0 || !in_array($word, $minor, true))) {
                return false;
            }
        }

        return $words !== [];
    }

    /**
     * The text of a `## ` section of a note, up to the next section.
     *
     * @param  string  $note
     * @param  string  $heading
     * @return string
     */
    private static function section(string $note, string $heading): string
    {
        $pattern = '/^## ' . preg_quote($heading, '/') . '\n(.*?)(?=^## |\z)/ms';

        return preg_match($pattern, $note, $matches) === 1 ? $matches[1] : '';
    }

    /**
     * The backticked source, configuration or database paths a section anchors.
     *
     * @param  string  $section
     * @return list<string>
     */
    private static function anchoredFiles(string $section): array
    {
        preg_match_all('/`((?:src|config|database)\/[^`\s]+\.php)`/', $section, $files);

        return $files[1];
    }

    /**
     * Each backticked test file a section cites, with its methods; a method
     * before any file goes under `?`.
     *
     * @param  string  $section
     * @return array<string, list<string>>
     */
    private static function citedTests(string $section): array
    {
        preg_match_all('/`([^`]+)`/', $section, $spans);

        $cited = [];
        $file  = null;

        foreach ($spans[1] as $span) {

            if (preg_match('/\Atests\/\S+Test\.php\z/', $span) === 1) {
                $file = $span;
                $cited[$file] ??= [];

                continue;
            }

            if (preg_match('/\Atest[A-Z]\w*\z/', $span) !== 1) {
                continue;
            }

            $cited[$file ?? '?'][] = $span;
        }

        return $cited;
    }

    /**
     * The case values of every event-defining enum in `src/`.
     *
     * @return list<string>
     */
    private static function shippedCodes(): array
    {
        $root    = self::root() . '/src/';
        $classes = [];
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $classes[] = self::PACKAGE_NAMESPACE . str_replace('/', '\\', substr($file->getPathname(), strlen($root), -4));
        }

        sort($classes);

        return self::codesOf($classes);
    }

    /**
     * The case values of those classes that are enums defining events.
     *
     * @param  list<string>  $classes
     * @return list<string>
     */
    private static function codesOf(array $classes): array
    {
        $codes = [];

        foreach ($classes as $class) {

            if (!enum_exists($class) || !is_subclass_of($class, DefinesAuditEvents::class)) {
                continue;
            }

            foreach ($class::cases() as $case) {
                $codes[] = (string) $case->value;
            }
        }

        return $codes;
    }

    /**
     * The codes that sit under none of the reserved prefixes.
     *
     * @param  list<string>  $codes
     * @return list<string>
     */
    private static function codesOutsideTheReservedPrefixes(array $codes): array
    {
        return array_values(array_diff($codes, self::codesUnderTheReservedPrefixes($codes)));
    }

    /**
     * The codes that sit under one of the reserved prefixes.
     *
     * @param  list<string>  $codes
     * @return list<string>
     */
    private static function codesUnderTheReservedPrefixes(array $codes): array
    {
        return array_values(array_filter($codes, static function (string $code): bool {

            foreach (self::RESERVED_PREFIXES as $prefix) {
                if (str_starts_with($code, $prefix)) {
                    return true;
                }
            }

            return false;
        }));
    }

    /**
     * The first string argument of each `record(`, `event(`, `accessed(` and
     * `for(` call, and each upper-case enum case's value, in order.
     *
     * @param  string  $code
     * @return list<string>
     */
    private static function exampleCodesIn(string $code): array
    {
        $pattern = '/(?:(?<![\w$])(?:record|event|accessed|for)\(\s*|\bcase\s+[A-Z][A-Z0-9_]*\s*=\s*)' . self::LITERAL . '/';

        preg_match_all($pattern, $code, $matches, PREG_SET_ORDER);

        return array_map(static fn (array $match): string => self::literal($match), $matches);
    }

    /**
     * The suite's other namespaces, Composer packages and configuration keys
     * the code names.
     *
     * @param  string  $code
     * @return list<string>
     */
    private static function foreignNamesIn(string $code): array
    {
        preg_match_all('/SineMacula(\\\{1,2})Laravel\1(?!AuditLog\b)[A-Za-z_]\w*/', $code, $namespaces);
        preg_match_all('/sinemacula\/laravel-(?!audit-log\b)[a-z][a-z0-9-]*/i', $code, $packages);
        preg_match_all('/(?:\bconfig|\bConfig::\w+)\(\s*\[?\s*' . self::LITERAL . '/', $code, $reads, PREG_SET_ORDER);

        $configs = [];

        foreach ($reads as $read) {

            $file = explode('.', self::literal($read))[0];

            if ($file === self::CONFIG_KEY || in_array($file, self::LARAVEL_CONFIG, true)) {
                continue;
            }

            $configs[] = 'config: ' . $file;
        }

        return [...$namespaces[0], ...$packages[0], ...$configs];
    }

    /**
     * Whether the text has a table row starting with the event's class name.
     *
     * @param  string  $text
     * @param  string  $class
     * @return bool
     */
    private static function hasEventRow(string $text, string $class): bool
    {
        return preg_match('/^\| `' . preg_quote($class, '/') . '`/m', $text) === 1;
    }

    /**
     * The methods called on the `AuditLog` facade in the text, each once, in
     * the order they first appear.
     *
     * @param  string  $text
     * @return list<string>
     */
    private static function auditLogCallsIn(string $text): array
    {
        preg_match_all('/(?<![\w$])AuditLog\s*::\s*(\w+)\s*\(/', $text, $matches);

        return array_values(array_unique($matches[1]));
    }

    /**
     * The calls the documentation may show on the facade.
     *
     * @return list<string>
     */
    private static function knownAuditLogCalls(): array
    {
        return [...self::callsDeclaredOn(Recorder::class), ...self::callsDeclaredOn(AuditLog::class), ...self::PLANNED_CALLS];
    }

    /**
     * The public methods the class declares itself, constructor and magic
     * methods aside.
     *
     * @param  class-string  $class
     * @return list<string>
     */
    private static function callsDeclaredOn(string $class): array
    {
        $calls = [];

        foreach ((new \ReflectionClass($class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->getDeclaringClass()->getName() !== $class || str_starts_with($method->getName(), '__')) {
                continue;
            }

            $calls[] = $method->getName();
        }

        return $calls;
    }

    /**
     * The text of a matched `LITERAL`, whichever quotes it is in.
     *
     * @param  array<int|string, string>  $match
     * @return string
     */
    private static function literal(array $match): string
    {
        return ($match[1] ?? '') !== '' ? $match[1] : ($match[2] ?? '');
    }

    /**
     * The section's code block holding the named channel, or nothing.
     *
     * @param  string  $section
     * @return string
     */
    private static function documentedChannel(string $section): string
    {
        preg_match_all('/^ *```[^\n]*\n(.*?)^ *```[ \t]*$/ms', $section, $blocks);

        foreach ($blocks[1] as $block) {
            if (str_contains($block, '\'audit-spill\'')) {
                return $block;
            }
        }

        return '';
    }

    /**
     * An entry of the channel, written as it is in configuration.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return string
     */
    private static function channelEntry(string $key, mixed $value): string
    {
        return sprintf('\'%s\' => %s', $key, self::channelValue($value));
    }

    /**
     * A value of the channel, written as it is in configuration.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     */
    private static function channelValue(mixed $value): string
    {
        if (is_array($value)) {
            $entries = array_map(self::channelEntry(...), array_keys($value), array_values($value));

            return '[' . implode(', ', $entries) . ']';
        }

        return match (true) {
            is_bool($value)                                 => $value ? 'true' : 'false',
            is_int($value)                                  => sprintf('0%o', $value),
            is_string($value) && class_exists($value)       => $value . '::class',
            is_string($value) && str_contains($value, "\n") => '"' . addcslashes($value, "\n") . '"',
            default                                         => '\'' . (is_string($value) ? $value : get_debug_type($value)) . '\'',
        };
    }

    /**
     * The contents of every fenced code block in the documentation, joined.
     *
     * @return string
     */
    private static function codeBlocks(): string
    {
        preg_match_all('/^ *(```|~~~)[^\n]*\n(.*?)^ *\1[ \t]*$/ms', self::documentation(), $matches);

        return implode("\n", $matches[2]);
    }

    /**
     * The Markdown without its fenced code blocks, so a `#` comment in a code
     * block is never read as a heading.
     *
     * @param  string  $markdown
     * @return string
     */
    private static function withoutCodeBlocks(string $markdown): string
    {
        return (string) preg_replace('/^ *(```|~~~)[^\n]*\n.*?^ *\1[ \t]*$/ms', '', $markdown);
    }

    /**
     * The text of the README, every guide and every design note.
     *
     * @return string
     */
    private static function documentation(): string
    {
        $root  = self::root();
        $files = [$root . '/README.md', ...(glob($root . '/docs/guides/*.md') ?: []), ...(glob($root . '/docs/design/*.md') ?: [])];

        return self::$documentation ??= implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
    }

    /**
     * A repository file, whitespace collapsed so a wrapped sentence matches.
     *
     * @param  string  $path
     * @return string
     */
    private static function prose(string $path): string
    {
        return self::collapsed(self::read($path));
    }

    /**
     * The text with every run of whitespace made one space.
     *
     * @param  string  $text
     * @return string
     */
    private static function collapsed(string $text): string
    {
        return (string) preg_replace('/\s+/', ' ', $text);
    }

    /**
     * The contents of a file of the repository.
     *
     * @param  string  $path
     * @return string
     */
    private static function read(string $path): string
    {
        $contents = file_get_contents(self::root() . $path);

        self::assertIsString($contents, sprintf('%s cannot be read.', $path));

        return $contents;
    }

    /**
     * The repository's root directory.
     *
     * @return string
     */
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
