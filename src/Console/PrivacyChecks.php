<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Config\SecretSetting;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use SineMacula\Laravel\AuditLog\Keys\KeySettings;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Keys\WrappingRing;
use SineMacula\Laravel\AuditLog\Privacy\KeyStoreUse;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;

/**
 * The privacy checks of `audit-log:check`: key settings and tables, restored or
 * unjournalled keys, unheld wrapping keys, and a restore behind the anchor.
 *
 * Nothing is unwrapped, and only key ids and sequences are printed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrivacyChecks
{
    /** @var int Reconciliation rows read by one statement, newest first. */
    public const int JOURNAL_PAGE = 100;

    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding> The key findings that are a problem, in the order they are reported. */
    private const array REPORTED = [Finding::KEY_RESTORED, Finding::KEY_DESTROYED_UNJOURNALLED];

    /** @var string A failure to read, by what could not be read and the class of what was thrown. */
    private const string UNREADABLE = '%s could not be read (%s).';

    /** @var string Why the application keys the wrapping keys would be derived from are refused. */
    private const string DERIVED_RING = '`app.key` and each of `app.previous_keys` must be at least 32 bytes, or `base64:` followed by the encoding of at least'
        . ' 32 bytes, to derive the wrapping keys when `audit-log.privacy.keys` is empty.';

    /** @var string The problem of keys an erased owner holds again, by their count, its noun and verb, and the first key's id. */
    private const string RESTORED_KEYS = '%d %s of erased owners %s a key again (`key_restored`%s); a restore from before an erasure brings its keys back,'
        . ' so re-apply the erasures since with `audit-log:erase --reapply=<file>`.';

    /** @var string The problem of keys destroyed with no erasure journalled, by their count, its noun and verb, and the first key's id. */
    private const string UNJOURNALLED_KEYS = '%d %s no wrapped key that a verified erasure destroyed (`key_destroyed_unjournalled`%s); run `audit-log:verify`,'
        . ' and after a restore re-apply the erasures with `audit-log:erase --reapply=<file>`.';

    /** @var string The problem of keys wrapped under a wrapping key the ring does not hold, by their count, its noun and verb, and the first key's id. */
    private const string UNHELD_WRAPPING_KEYS = '%d %s wrapped under a wrapping key the ring does not hold%s, so %s; put the wrapping key back in'
        . ' `audit-log.privacy.keys` or `app.previous_keys`, then run `audit-log:rewrap`.';

    /** @var string The problem of a database that does not hold the seal its anchor holds at the head's sequence. */
    private const string RESTORED_DATABASE = 'The database does not hold the seal its anchor holds at sequence %d, so it was restored from a backup or rewritten;'
        . ' re-apply every erasure since with `audit-log:erase --reapply=<file>`, which reconciles the restore, and run `audit-log:verify`.';

    /** @var string The problem of an anchor whose head cannot be read, by the class of what was thrown. */
    private const string UNREAD_HEAD = 'The anchor\'s head could not be read (%s), so a database restored behind it cannot be ruled out.';

    /** @var string The note on a field encrypter that is not the package's, by its class. */
    private const string CUSTOM_ENCRYPTER = 'The bound field encrypter `%s` keeps its keys where the package cannot see them, so `audit-log:erase` refuses,'
        . ' `holdingDataOf()` throws, and the key store is neither checked nor verified.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Console\SchemaChecks  $schemas
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private ConfigRepository $config,

        /** The connections the tables are read on. */
        private DatabaseManager $database,

        /** The checks of each table's shape. */
        private SchemaChecks $schemas,

        /** The container the encrypter, the anchor and the verifiers are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * A reader for each owners' key setting, then the application keys the
     * wrapping keys derive from when nothing else reads them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     */
    public static function readers(ConfigRepository $config): array
    {
        $keys = new KeySettings($config, new IntegritySettings($config));

        return [
            KeyTables::subjectKeysTable(...),
            KeyTables::ownerErasuresTable(...),
            KeyTables::keyUsesTable(...),
            $keys->explicitKeys(...),
            $keys->currentKeyId(...),
            $keys->rewrapBatch(...),
            static function () use ($config): void {
                self::checkDerivedRing($config);
            },
        ];
    }

    /**
     * The privacy subject's checks, or none while a setting it reads is
     * malformed or the storage connection unconfigured, which others report.
     *
     * @return array<string, list<\Closure(): list<string>>>
     */
    public function subject(): array
    {
        try {
            self::validate($this->config);

            $configured = is_array($this->config->get('database.connections.' . StorageConnection::resolvedName()));
        } catch (\InvalidArgumentException) {
            return [];
        }

        return $configured ? ['privacy' => [$this->problems(...)]] : [];
    }

    /**
     * Every privacy problem: a malformed setting, which stops the rest, then
     * the tables' shapes, the keys and a restore behind the anchor.
     *
     * @return list<string>
     */
    public function problems(): array
    {
        try {
            self::validate($this->config);

            $name = StorageConnection::resolvedName();
        } catch (\InvalidArgumentException $exception) {
            return [$exception->getMessage()];
        }

        if ((new EngineChecks($this->database))->blockingProblem($name) !== null) {
            return [];
        }

        return $this->storedProblems($name);
    }

    /**
     * The note on a bound field encrypter that is not the package's; one that
     * cannot be resolved is reported as a problem.
     *
     * @return list<string>
     */
    public function notes(): array
    {
        try {
            $encrypter = $this->container->make(FieldEncrypter::class);
        } catch (\Throwable) {
            return [];
        }

        return KeyStoreUse::covers($encrypter) ? [] : [sprintf(self::CUSTOM_ENCRYPTER, KeyStoreUse::describe($encrypter))];
    }

    /**
     * The schema problems of the three key tables on the storage connection.
     *
     * @param  string  $connection
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function tableProblems(string $connection): array
    {
        return [
            ...$this->schemas->problems($connection, KeyTables::subjectKeysTable(), TableShape::subjectKeys()),
            ...$this->schemas->problems($connection, KeyTables::ownerErasuresTable(), TableShape::ownerErasures()),
            ...$this->schemas->problems($connection, KeyTables::keyUsesTable(), TableShape::keyUses()),
        ];
    }

    /**
     * The problems of the key tables' shapes, then, once they have it, the keys
     * and a restore behind the anchor.
     *
     * @param  string  $name
     * @return list<string>
     */
    private function storedProblems(string $name): array
    {
        // A failed statement throws an undeclared `QueryException`, whose
        // message holds the statement
        try {
            $tables = $this->tableProblems($name);
        } catch (\PDOException $exception) { // @phpstan-ignore catch.neverThrown
            return [sprintf('The storage connection [%s] could not be read (%s).', $name, get_debug_type($exception))];
        }

        if ($tables !== []) {
            return $tables;
        }

        $connection = $this->database->connection($name);

        return [...$this->keyProblems($connection), ...$this->restoreProblems($connection)];
    }

    /**
     * The problems of keys restored or destroyed without a journalled erasure,
     * then of unheld wrapping keys; none without the package's key store.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function keyProblems(Connection $connection): array
    {
        try {
            $encrypter = $this->container->make(FieldEncrypter::class);
            $tally     = new VerificationTally;

            if (!KeyStoreUse::covers($encrypter)) {
                return [];
            }

            $this->container->make(KeyStoreVerifier::class)->verify($tally, true, false);
        } catch (\Throwable $exception) {
            return [sprintf(self::UNREADABLE, 'The key store', get_debug_type($exception))];
        }

        $found = [];

        foreach ($tally->findings() as $finding) {
            $found[$finding->finding->value] = $finding;
        }

        $problems = [];

        foreach (self::REPORTED as $reported) {
            if (!isset($found[$reported->value])) {
                continue;
            }

            $problems[] = self::findingProblem($found[$reported->value]);
        }

        return [...$problems, ...$this->unheldKeyProblems($connection)];
    }

    /**
     * The problem of live or superseded keys under a wrapping key the ring does
     * not hold, judged by ids alone; none without the package's own wrapper.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function unheldKeyProblems(Connection $connection): array
    {
        try {
            $keys = $connection->table(KeyTables::subjectKeysTable())
                ->useWritePdo()
                ->whereIn('state', [KeyState::LIVE->value, KeyState::SUPERSEDED->value])
                ->whereNotNull('wrap_key_id');

            /** @var list<scalar> $named */
            $named  = $this->container->make(KeyWrapper::class) instanceof LocalKeyWrapper ? (clone $keys)->distinct()->pluck('wrap_key_id')->all() : [];
            $unheld = $named  === [] ? [] : array_values(array_diff(array_map(strval(...), $named), $this->container->make(WrappingRing::class)->ids()));
            $count  = $unheld === [] ? 0 : (clone $keys)->whereIn('wrap_key_id', $unheld)->count();
            $first  = $unheld === [] ? null : (clone $keys)->whereIn('wrap_key_id', $unheld)->orderBy('id')->value('id');
        } catch (\Throwable $exception) {
            return [sprintf(self::UNREADABLE, 'The subject keys\' wrapping key ids', get_debug_type($exception))];
        }

        if ($count === 0) {
            return [];
        }

        $named = is_string($first) && preg_match(SealEnvelope::UUID_PATTERN, $first) === 1 ? " (the first `{$first}`)" : '';

        return [$count === 1
            ? sprintf(self::UNHELD_WRAPPING_KEYS, 1, 'key is', $named, 'it cannot be unwrapped')
            : sprintf(self::UNHELD_WRAPPING_KEYS, $count, 'keys are', $named, 'they cannot be unwrapped')];
    }

    /**
     * The problem of a database without its anchor's head seal, unless a
     * verified reconciliation names that head; none without an anchor to ask.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function restoreProblems(Connection $connection): array
    {
        // Asked first, so a seal written after it never reads as one the
        // database does not hold
        try {
            $head = $this->anchoredHead();
        } catch (\Throwable $exception) {
            return [sprintf(self::UNREAD_HEAD, get_debug_type($exception))];
        }

        try {
            $problems = $head === null || $this->holds($connection, $head) || $this->isReconciled($connection, $head)
                ? []
                : [sprintf(self::RESTORED_DATABASE, $head->sequence)];
        } catch (\Throwable $exception) {
            $problems = [sprintf(self::UNREADABLE, 'The seals or the lifecycle journal', get_debug_type($exception))];
        }

        return $problems;
    }

    /**
     * The anchor's head, or `null` when there is none or no anchor that can
     * report one; throws when the anchor cannot be resolved or read.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    private function anchoredHead(): ?AnchoredHead
    {
        if (!$this->isAnchorConfigured()) {
            return null;
        }

        $anchor = $this->container->make(CheckpointAnchor::class);

        return $anchor instanceof NullAnchor || !$anchor->supportsDiscovery() ? null : $anchor->latest();
    }

    /**
     * Whether the anchor's settings are well formed and a disk anchor's disk is
     * configured, so an anchor is never resolved on a missing disk.
     *
     * @return bool
     */
    private function isAnchorConfigured(): bool
    {
        $anchors = new AnchorSettings($this->config);

        try {
            $anchors->validate();

            return $anchors->driver() !== AnchorDriver::DISK || is_array($this->config->get("filesystems.disks.{$anchors->disk()}"));
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * Whether the database holds the anchored head: a seal at its sequence
     * stored with its digest.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $head
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function holds(Connection $connection, AnchoredHead $head): bool
    {
        $digest = $connection->table(IntegrityTables::checkpointsTable())->useWritePdo()->where('sequence', $head->sequence)->value('seal_digest');

        return $digest === $head->digest;
    }

    /**
     * Whether a believed `restore_reconciled` row names the anchored head,
     * reading those rows newest first a page at a time.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $head
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isReconciled(Connection $connection, AnchoredHead $head): bool
    {
        $signer   = $this->container->make(JournalSigner::class);
        $logId    = $this->container->make(SealSettings::class)->logId();
        $believed = static fn (object $stored): bool => self::reconciles((array) $stored, $signer, $logId, $head);
        $before   = PHP_INT_MAX;

        do {
            $page = $connection->table(LifecycleTables::journalTable())
                ->useWritePdo()
                ->where('kind', JournalKind::RESTORE_RECONCILED->value)
                ->where('sequence', '<', $before)
                ->orderByDesc('sequence')
                ->limit(self::JOURNAL_PAGE)
                ->get()
                ->all();

            if (array_filter($page, $believed) !== []) {
                return true;
            }

            $full   = count($page) === self::JOURNAL_PAGE;
            $before = IntegerSetting::parse(array_pop($page)->sequence ?? null) ?? 0;
        } while ($full && $before > 0);

        return false;
    }

    /**
     * Whether the row is a believed reconciliation of the head: this log's,
     * digest and signature verified, and naming the head's sequence and digest.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  string  $logId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $head
     * @return bool
     */
    private static function reconciles(#[\SensitiveParameter] array $stored, JournalSigner $signer, string $logId, AnchoredHead $head): bool
    {
        try {
            $journalRow = JournalRow::fromRow($stored, true);
            $believed   = $journalRow->logId === $logId && $journalRow->hasPayloadOfItsDigest() && $signer->verifies($journalRow);
            $payload    = $believed ? $journalRow->payloadMap() : null;
        } catch (\JsonException|\UnexpectedValueException|UnknownKeyException) {
            return false;
        }

        if ($payload === null) {
            return false;
        }

        return ($payload['anchored_sequence'] ?? null) === $head->sequence && ($payload['anchored_digest'] ?? null) === $head->digest;
    }

    /**
     * Read every setting the privacy problems are read with, failing on the
     * first malformed one.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function validate(ConfigRepository $config): void
    {
        $integrity = new IntegritySettings($config);
        $keys      = new KeySettings($config, $integrity);

        KeyTables::validate();

        if ($keys->currentKeyId() === null) {
            self::derivedKeys($keys);
        }

        $keys->rewrapBatch();
        $integrity->validate();

        (new SealSettings($config))->logId();

        LifecycleTables::journalTable();
        IntegrityTables::checkpointsTable();
    }

    /**
     * The problem a reported key finding gives, naming the first key's id only
     * when it is a lower-case UUID, so no byte a table holds reaches a console.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RunFinding  $finding
     * @return string
     */
    private static function findingProblem(RunFinding $finding): string
    {
        $one   = $finding->count === 1;
        $id    = $finding->firstBadId;
        $first = $id !== null && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1 ? ", the first `{$id}`" : '';

        if ($finding->finding === Finding::KEY_RESTORED) {
            return sprintf(self::RESTORED_KEYS, $finding->count, $one ? 'key' : 'keys', $one ? 'holds' : 'hold', $first);
        }

        return sprintf(self::UNJOURNALLED_KEYS, $finding->count, $one ? 'key holds' : 'keys hold', $first);
    }

    /**
     * Read the application keys the wrapping keys derive from, unless another
     * check already reads or lists them.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkDerivedRing(ConfigRepository $config): void
    {
        $integrity = new IntegritySettings($config);
        $keys      = new KeySettings($config, $integrity);

        if ($keys->explicitKeys() !== [] || $integrity->explicitKeys() === []) {
            return;
        }

        try {
            self::derivedKeys($keys);
        } catch (\InvalidArgumentException $exception) {
            if (self::isListedByRedaction($config)) {
                return;
            }

            throw $exception;
        }
    }

    /**
     * Read the application keys the wrapping keys are derived from, refusing
     * malformed ones as the wrapping ring's own problem.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeySettings  $keys
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function derivedKeys(KeySettings $keys): void
    {
        try {
            $keys->applicationKeys();
        } catch (\InvalidArgumentException) {
            // The integrity settings' refusal names the integrity key
            throw new \InvalidArgumentException(self::DERIVED_RING);
        }
    }

    /**
     * Whether the redaction settings list a malformed `app.key`: the redaction
     * key is empty, so it falls back to `app.key`, and `app.key` is not a key.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return bool
     */
    private static function isListedByRedaction(ConfigRepository $config): bool
    {
        try {
            $explicit = (new RedactionSettings($config))->explicitKey();
        } catch (\InvalidArgumentException) {
            // A malformed redaction key is listed instead; it reads no app key
            return false;
        }

        return $explicit === null && SecretSetting::decode($config->get('app.key')) === null;
    }
}
