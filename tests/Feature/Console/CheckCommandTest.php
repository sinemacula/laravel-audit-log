<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Filesystem\Factory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\MySqlBuilder;
use Illuminate\Database\SQLiteDatabaseDoesNotExistException;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Database\VersionReportingPdo;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:check`: each subject's problems, the exit code,
 * and that no secret or setting value is printed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
final class CheckCommandTest extends TestCase
{
    use MockeryPHPUnitIntegration, WritesTheJournal;

    /** @var string The note on the default channel of a default install, which is not the documented spill channel. */
    private const string SPILL_NOTE = '[spill] The channel [stack] is not the documented file format, so replaying what it holds is unverified,'
        . ' and whole records in plaintext go to it and to everything it feeds.';

    /** @var list<string> What a run prints when nothing has a problem, the note on the default channel last. */
    private const array EVERY_SUBJECT_OK = [
        '[config] OK', '[connections] OK', '[schema] OK', '[integrity] OK', '[delivery] OK', '[lifecycle] OK', '[privacy] OK', self::SPILL_NOTE,
    ];

    /** @var list<string> Absolute paths to the shipped migrations the schema subject checks, in run order. */
    private const array MIGRATION_PATHS = [
        __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000600_create_audit_log_artifacts_table.php',
    ];

    /** @var string The table a test migrates under a name of its own. */
    private const string CUSTOM_TABLE = 'audit_custom_entries';

    /** @var string The artifacts table a test migrates; its own name avoids PostgreSQL index name clashes. */
    private const string CUSTOM_ARTIFACTS_TABLE = 'audit_custom_artifacts';

    /** @var string A secret one byte short of the 32 an integrity key needs. */
    private const string SHORT_SECRET = 'a-secret-one-byte-short-of-32!!';

    /** @var list<string> Absolute paths to the shipped integrity migration files, in the order they run. */
    private const array INTEGRITY_MIGRATION_PATHS = [
        __DIR__ . '/../../../database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php',
    ];

    /** @var array<string, string> The integrity tables a test migrates under names of their own, by setting; own names avoid PostgreSQL index name clashes. */
    private const array CUSTOM_INTEGRITY_TABLES = [
        'audit-log.integrity.checkpoints_table' => 'audit_custom_checkpoints',
        'audit-log.integrity.members_table'     => 'audit_custom_members',
        'audit-log.integrity.state_table'       => 'audit_custom_state',
    ];

    /** @var list<string> Absolute paths to the shipped lifecycle migration files, in the order they run. */
    private const array LIFECYCLE_MIGRATION_PATHS = [
        __DIR__ . '/../../../database/migrations/2026_11_02_000700_create_audit_log_lifecycle_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000800_create_audit_log_holds_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000900_create_audit_log_lifecycle_lock_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_001000_create_audit_log_import_batches_table.php',
    ];

    /** @var array<string, string> The lifecycle tables a test migrates under names of their own, by setting; own names avoid PostgreSQL index name clashes. */
    private const array CUSTOM_LIFECYCLE_TABLES = [
        'audit-log.lifecycle.journal_table' => 'audit_custom_journal',
        'audit-log.lifecycle.holds_table'   => 'audit_custom_holds',
        'audit-log.lifecycle.lock_table'    => 'audit_custom_lock',
        'audit-log.import.batches_table'    => 'audit_custom_batches',
    ];

    /** @var list<string> Absolute paths to the shipped owners' key migration files, in the order they run. */
    private const array KEY_MIGRATION_PATHS = [
        __DIR__ . '/../../../database/migrations/2026_11_02_001100_create_audit_log_subject_keys_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_001200_create_audit_log_owner_erasures_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_001300_create_audit_log_key_uses_table.php',
    ];

    /** @var array<string, string> The owners' key tables a test migrates under names of their own, by setting; own names avoid PostgreSQL index name clashes. */
    private const array CUSTOM_KEY_TABLES = [
        'audit-log.privacy.subject_keys_table'   => 'audit_custom_subject_keys',
        'audit-log.privacy.owner_erasures_table' => 'audit_custom_owner_erasures',
        'audit-log.privacy.key_uses_table'       => 'audit_custom_key_uses',
    ];

    /** @var string What the wrapping keys derived from a missing or malformed application key are refused with. */
    private const string MALFORMED_WRAPPING_APPLICATION_KEY = '[config] `app.key` and each of `app.previous_keys` must be at least 32 bytes, or `base64:`'
        . ' followed by the encoding of at least 32 bytes, to derive the wrapping keys when `audit-log.privacy.keys` is empty.';

    /** @var array<string, array<string, string>|string> An explicit wrapping ring whose settings all pass, so none of them reads `app.key`. */
    private const array WRAPPING_RING = [
        'audit-log.privacy.keys'    => ['w1' => 'a-wrapping-secret-of-32-bytes-ok'],
        'audit-log.privacy.current' => 'w1',
    ];

    /** @var string What a missing table is asked to be created by, after its name and connection. */
    private const string PUBLISH = '; publish and run the migrations (`vendor:publish --tag=audit-log-migrations`, then `migrate`).';

    /** @var string How a log id that does not fit its grammar is refused. */
    private const string MALFORMED_LOG_ID = '[config] `audit-log.integrity.log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens,'
        . ' starting with a letter or a digit.';

    /** @var string What a disk anchor's disk that is not configured is reported as. */
    private const string UNCONFIGURED_DISK = '[integrity] The disk [anchors] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.';

    /** @var string The configured table no test migrates. */
    private const string ABSENT_TABLE = 'audit_absent_entries';

    /** @var string The longest artifacts table's name the setting accepts, which a test migrates. */
    private const string LONGEST_ARTIFACTS_TABLE = 'audit_log_artifacts_under_the_longest_name_xxxx';

    /** @var string The configured artifacts table no test migrates. */
    private const string ABSENT_ARTIFACTS_TABLE = 'audit_absent_artifacts';

    /** @var array<string, int|string> A refused value for each configuration leaf, by its path under `audit-log`. */
    private const array BAD_LEAVES = [
        'storage.connection'                        => 123,
        'storage.maintenance_connection'            => 123,
        'entries.table'                             => 'audit-log',
        'entries.artifacts_table'                   => 'audit-artifacts',
        'integrity.keys'                            => 'x',
        'integrity.current'                         => 'k1',
        'actor.guards'                              => 'web',
        'context.trust_request_id'                  => 'yes',
        'context.request_id_header'                 => 'X Request',
        'context.trust_traceparent'                 => 'yes',
        'definitions.require_registered'            => '1',
        'capture.laravel.except_guards'             => 'web',
        'capture.laravel.identifier_key'            => 'e mail',
        'capture.gate.enabled'                      => 'true',
        'capture.gate.only_abilities'               => 'update',
        'capture.gate.except_abilities'             => 'update',
        'capture.gate.reason_codes'                 => 'plan_expired',
        'capture.bulk.max_members'                  => 0,
        'capture.bulk.max_bytes'                    => 65535,
        'read.max_per_page'                         => 0,
        'export.chunk'                              => 99,
        'source.id'                                 => 42,
        'source.region'                             => 42,
        'redaction.keys'                            => 'password',
        'redaction.key'                             => 'short',
        'redaction.identifiers'                     => 'maybe',
        'redaction.ip'                              => 'partial',
        'redaction.max_bytes'                       => 8191,
        'redaction.max_context_bytes'               => 1023,
        'failure.mode'                              => 'maybe',
        'failure.log_channel'                       => 42,
        'delivery.mode'                             => 'queue',
        'delivery.outbox.connection'                => 42,
        'delivery.outbox.table'                     => 'audit-outbox',
        'delivery.outbox.lease_seconds'             => 29,
        'delivery.outbox.max_attempts'              => 0,
        'delivery.outbox.backoff_seconds'           => 0,
        'delivery.deliveries_table'                 => 'audit-deliveries',
        'integrity.log_id'                          => '../escape',
        'integrity.checkpoints_table'               => 'Seals',
        'integrity.members_table'                   => 'seal-members',
        'integrity.state_table'                     => '1state',
        'integrity.seal.schedule'                   => 'often',
        'integrity.seal.sweep_schedule'             => 'nightly',
        'integrity.seal.batch'                      => 99,
        'integrity.seal.max_batches'                => 0,
        'integrity.seal.lookback_seconds'           => 2592001,
        'integrity.seal.settle_seconds'             => 3601,
        'integrity.seal.max_attempts'               => 0,
        'integrity.verify.schedule'                 => '60 * * * *',
        'integrity.verify.max_unsealed_age_seconds' => 599,
        'integrity.anchor.driver'                   => 's3',
        'integrity.anchor.disk'                     => 42,
        'integrity.anchor.path'                     => '../anchors',
        'integrity.anchor.batch'                    => 0,
        'lifecycle.journal_table'                   => 'Journal',
        'lifecycle.holds_table'                     => 'audit-holds',
        'lifecycle.lock_table'                      => '1lock',
        'import.batches_table'                      => 'Batches',
        'retention.after_days'                      => 36501,
        'retention.categories'                      => 'security',
        'retention.preserve'                        => 'security',
        'retention.batch'                           => 99,
        'retention.max_seconds'                     => 59,
        'retention.schedule'                        => 'nightly',
        'import.chunk'                              => 99,
        'import.max_skew_seconds'                   => 86401,
        'import.max_line_bytes'                     => 1023,
        'privacy.keys'                              => 'x',
        'privacy.current'                           => 'w1',
        'privacy.subject_keys_table'                => 'Keys',
        'privacy.owner_erasures_table'              => 'owner-erasures',
        'privacy.key_uses_table'                    => '1uses',
        'privacy.rewrap_batch'                      => 99,
        'monitor.seal_minutes'                      => 4,
        'monitor.daily_minutes'                     => 59,
        'monitor.outbox_minutes'                    => 0,
    ];

    /** @var array<string, array<string, string>|string> An explicit ring whose settings all pass, so none of them reads `app.key`. */
    private const array RING = [
        'audit-log.integrity.keys'    => ['k1' => 'a-secret-of-exactly-32-bytes-ok!'],
        'audit-log.integrity.current' => 'k1',
    ];

    /** @var string What a test's bad value carries, and the output must never hold. */
    private const string SENTINEL = 'sentinel-7f3a9c';

    /** @var string The message of a malformed list of guards. */
    private const string MALFORMED_GUARDS = '[config] `audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.';

    /** @var string The message of a malformed source id. */
    private const string MALFORMED_SOURCE_ID = '[config] `audit-log.source.id` must be from 1 to 64 characters, with no control characters.';

    /** @var string The message of a malformed source region. */
    private const string MALFORMED_SOURCE_REGION = '[config] `audit-log.source.region` must be null or empty, or from 1 to 32 characters, with no control characters.';

    /** @var string The message of a malformed header name. */
    private const string MALFORMED_HEADER = '[config] `audit-log.context.request_id_header` must be a header name of 1 to 64 characters.';

    /** @var string The message of a malformed flag trusting a request id. */
    private const string MALFORMED_TRUST_REQUEST_ID = '[config] `audit-log.context.trust_request_id` must be true or false.';

    /** @var string The message of a malformed flag trusting a `traceparent`. */
    private const string MALFORMED_TRUST_TRACEPARENT = '[config] `audit-log.context.trust_traceparent` must be true or false.';

    /** @var string The message of a malformed flag requiring a registered definition. */
    private const string MALFORMED_REQUIRE_REGISTERED = '[config] `audit-log.definitions.require_registered` must be true or false.';

    /** @var string The message of malformed redaction key names. */
    private const string MALFORMED_REDACTION_KEYS = '[config] `audit-log.redaction.keys` must be a list of key names, each of at least one token.';

    /** @var string The message of a malformed redaction key. */
    private const string MALFORMED_REDACTION_KEY = '[config] `audit-log.redaction.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes.';

    /** @var string The message of a missing application key the redaction key would derive from. */
    private const string MISSING_APPLICATION_KEY = '[config] `app.key` must be set to derive the redaction key when `audit-log.redaction.key` is empty.';

    /** @var string The message of a malformed application key the redaction key would derive from. */
    private const string MALFORMED_APPLICATION_KEY = '[config] `app.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes,'
        . ' to derive the redaction key.';

    /** @var string The message of a missing application key the integrity key would derive from. */
    private const string MISSING_INTEGRITY_APPLICATION_KEY = '[config] `app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.';

    /** @var string The message of a malformed application key the integrity key would derive from. */
    private const string MALFORMED_INTEGRITY_APPLICATION_KEY = '[config] `app.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes,'
        . ' to derive the integrity key.';

    /** @var string The message of a malformed identifier mode. */
    private const string MALFORMED_IDENTIFIERS = '[config] `audit-log.redaction.identifiers` must be `hash` or `drop`.';

    /** @var string The message of a malformed IP mode. */
    private const string MALFORMED_IP = '[config] `audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.';

    /** @var string The message of a malformed properties budget. */
    private const string MALFORMED_MAX_BYTES = '[config] `audit-log.redaction.max_bytes` must be an integer from 8192 to 16777216.';

    /** @var string The message of a malformed context budget. */
    private const string MALFORMED_MAX_CONTEXT_BYTES = '[config] `audit-log.redaction.max_context_bytes` must be an integer from 1024 to 16777216.';

    /** @var string The message of a malformed failure mode. */
    private const string MALFORMED_FAILURE_MODE = '[config] `audit-log.failure.mode` must be `report` or `throw`.';

    /** @var string The message of a malformed spill channel. */
    private const string MALFORMED_LOG_CHANNEL = '[config] `audit-log.failure.log_channel` must be a channel name of 1 to 64 characters, or null or empty for the default channel.';

    /** @var string The message of a malformed delivery mode. */
    private const string MALFORMED_DELIVERY_MODE = '[config] `audit-log.delivery.mode` must be `sync` or `outbox`.';

    /** @var string The message of a malformed outbox table name. */
    private const string MALFORMED_OUTBOX_TABLE = '[config] `audit-log.delivery.outbox.table` must be a table name of 1 to 47 lower-case letters, digits and underscores'
        . ' that does not start with a digit.';

    /** @var string The message of a malformed deliveries table name. */
    private const string MALFORMED_DELIVERIES_TABLE = '[config] `audit-log.delivery.deliveries_table` must be a table name of 1 to 47 lower-case letters, digits and underscores'
        . ' that does not start with a digit.';

    /** @var string The problem of an excepted guard `auth.guards` does not configure, by its name. */
    private const string UNCONFIGURED_EXCEPT_GUARD = '[config] The guard [%s] that `audit-log.capture.laravel.except_guards` names is not configured in `auth.guards`.';

    /** @var list<string> Files a test created, removed when it ends. */
    private array $files = [];

    /**
     * Register the command directly so the tests do not depend on the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new CheckCommand);

        // Pin a default install's channel so the spill note never varies
        app(ConfigRepository::class)->set('logging.default', 'stack');

        // The package's default bindings, whether or not the provider has run
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bindIf(KeyWrapper::class, LocalKeyWrapper::class);
    }

    /**
     * Drop the tables a test migrated under its own names and remove its files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (app(ConfigRepository::class)->has('database.connections.custom')) {
            Schema::connection('custom')->dropIfExists(self::CUSTOM_TABLE);
            Schema::connection('custom')->dropIfExists(self::CUSTOM_ARTIFACTS_TABLE);

            foreach ([...self::CUSTOM_INTEGRITY_TABLES, ...self::CUSTOM_LIFECYCLE_TABLES, ...self::CUSTOM_KEY_TABLES] as $table) {
                Schema::connection('custom')->dropIfExists($table);
            }
        }

        Schema::connection(self::CONNECTION)->dropIfExists(self::LONGEST_ARTIFACTS_TABLE);

        CarbonImmutable::setTestNow();

        foreach ($this->files as $file) {

            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * An install the shipped migration created passes, each subject in order.
     *
     * @return void
     */
    public function testAGoodInstallPasses(): void
    {
        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * A custom prefixed table and connection with a key ring pass.
     *
     * @return void
     */
    public function testACustomTableAndConnectionPass(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.custom', [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'app_']);
        $config->set('audit-log.storage.connection', 'custom');
        $config->set('audit-log.storage.maintenance_connection', 'custom');
        $config->set('audit-log.entries.table', self::CUSTOM_TABLE);
        $config->set('audit-log.entries.artifacts_table', self::CUSTOM_ARTIFACTS_TABLE);
        $config->set('audit-log.integrity.keys', ['k1' => 'base64:' . base64_encode(str_repeat('k', 32))]);
        $config->set('audit-log.integrity.current', 'k1');
        $config->set(self::CUSTOM_INTEGRITY_TABLES);
        $config->set(self::CUSTOM_LIFECYCLE_TABLES);
        $config->set(self::CUSTOM_KEY_TABLES);

        $this->migrate();

        [, $before] = $this->check();

        $this->migrateIntegrityTables();
        $this->migrateLifecycleTables();
        $this->migrateKeyTables();

        [$code, $output] = $this->check();

        self::assertContains('[integrity] The checkpoints table `audit_custom_checkpoints` does not exist on connection [custom]' . self::PUBLISH, $before);
        self::assertContains('[lifecycle] The lifecycle journal table `audit_custom_journal` does not exist on connection [custom]' . self::PUBLISH, $before);
        self::assertContains('[privacy] The subject keys table `audit_custom_subject_keys` does not exist on connection [custom]' . self::PUBLISH, $before);
        self::assertTrue(Schema::connection('custom')->hasTable(self::CUSTOM_TABLE));
        self::assertTrue(Schema::connection('custom')->hasTable(self::CUSTOM_ARTIFACTS_TABLE));
        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * Rows of `[the settings changed, the one problem the change causes]`.
     *
     * @return iterable<string, array{0: array<string, array<array-key, int|string>|int|string|null>, 1: string}>
     */
    public static function provideBadSettings(): iterable
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';
        $other  = $driver === 'sqlite' ? 'pgsql' : 'sqlite';

        yield from [
            'a storage connection that is not a name' => [
                ['audit-log.storage.connection' => 123],
                '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            ],
            'a storage connection that is not a name beside a maintenance connection' => [
                ['audit-log.storage.connection' => 123, 'audit-log.storage.maintenance_connection' => 'testing'],
                '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            ],
            'a storage connection that is not a name, which no connection falls back to' => [
                ['audit-log.storage.connection' => 123, 'audit-log.storage.maintenance_connection' => 'testing', 'audit-log.delivery.outbox.connection' => 'testing'],
                '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            ],
            'a storage connection that is not configured' => [
                ['audit-log.storage.connection' => 'missing'],
                '[connections] The connection [missing] that `audit-log.storage.connection` names is not configured in `database.connections`.',
            ],
            'a maintenance connection that is not a name' => [
                ['audit-log.storage.maintenance_connection' => []],
                '[config] `audit-log.storage.maintenance_connection` must be a connection name, or null or empty for the storage connection.',
            ],
            'a maintenance connection that is not configured' => [
                ['audit-log.storage.maintenance_connection' => 'missing'],
                '[connections] The connection [missing] that `audit-log.storage.maintenance_connection` names is not configured in `database.connections`.',
            ],
            'a maintenance connection on another driver' => [
                ['database.connections.other' => ['driver' => $other, 'database' => 'elsewhere'], 'audit-log.storage.maintenance_connection' => 'other'],
                "[connections] The maintenance connection [other] uses the {$other} driver and the storage connection [testing] the {$driver} driver;"
                    . ' both must reach the same database.',
            ],
            'a table name of 48 characters' => [
                ['audit-log.entries.table' => str_repeat('a', 48)],
                '[config] `audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.',
            ],
            'a table name with a hyphen' => [
                ['audit-log.entries.table' => 'audit-log'],
                '[config] `audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.',
            ],
            'a table name with capitals, whose index names no engine reports as written' => [
                ['audit-log.entries.table' => 'AuditEntries'],
                '[config] `audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.',
            ],
            'a key ring that is not a map' => [
                ['audit-log.integrity.keys' => 'x'],
                '[config] `audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.',
            ],
            'a secret of 31 bytes' => [
                ['audit-log.integrity.keys' => ['k1' => self::SHORT_SECRET], 'audit-log.integrity.current' => 'k1'],
                '[config] `audit-log.integrity.keys.k1` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.',
            ],
            'a current key that is not in the ring' => [
                ['audit-log.integrity.keys' => ['k1' => str_repeat('k', 32)], 'audit-log.integrity.current' => 'k2'],
                '[config] `audit-log.integrity.current` must name a key in `audit-log.integrity.keys`.',
            ],
            'a current key without a ring' => [
                ['audit-log.integrity.current' => 'k1'],
                '[config] `audit-log.integrity.current` names a key, but `audit-log.integrity.keys` is empty; set both, or neither to derive the key from `app.key`.',
            ],
            'no application key to derive from' => [
                ['app.key' => ''],
                '[config] `app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.',
            ],
            'an empty list of guards'                  => [['audit-log.actor.guards' => []], self::MALFORMED_GUARDS],
            'guards that are a string'                 => [['audit-log.actor.guards' => 'web'], self::MALFORMED_GUARDS],
            'a guard that is not a string'             => [['audit-log.actor.guards' => [42]], self::MALFORMED_GUARDS],
            'guards that are a map'                    => [['audit-log.actor.guards' => ['first' => 'web']], self::MALFORMED_GUARDS],
            'an empty guard name'                      => [['audit-log.actor.guards' => ['']], self::MALFORMED_GUARDS],
            'a guard name of 65 characters'            => [['audit-log.actor.guards' => [str_repeat('g', 65)]], self::MALFORMED_GUARDS],
            'a guard name with a control character'    => [['audit-log.actor.guards' => ["web\x07"]], self::MALFORMED_GUARDS],
            'a request id flag that is a word'         => [['audit-log.context.trust_request_id' => 'yes'], self::MALFORMED_TRUST_REQUEST_ID],
            'a request id flag that is a number'       => [['audit-log.context.trust_request_id' => 1], self::MALFORMED_TRUST_REQUEST_ID],
            'a request id flag that is null'           => [['audit-log.context.trust_request_id' => null], self::MALFORMED_TRUST_REQUEST_ID],
            'a traceparent flag that is a word'        => [['audit-log.context.trust_traceparent' => 'yes'], self::MALFORMED_TRUST_TRACEPARENT],
            'a traceparent flag that is a number'      => [['audit-log.context.trust_traceparent' => 1], self::MALFORMED_TRUST_TRACEPARENT],
            'a traceparent flag that is null'          => [['audit-log.context.trust_traceparent' => null], self::MALFORMED_TRUST_TRACEPARENT],
            'a header name with a space'               => [['audit-log.context.request_id_header' => 'X Request'], self::MALFORMED_HEADER],
            'a header name that is not a string'       => [['audit-log.context.request_id_header' => 42], self::MALFORMED_HEADER],
            'an empty header name'                     => [['audit-log.context.request_id_header' => ''], self::MALFORMED_HEADER],
            'a header name of 65 characters'           => [['audit-log.context.request_id_header' => str_repeat('h', 65)], self::MALFORMED_HEADER],
            'a registered flag that is a digit'        => [['audit-log.definitions.require_registered' => '1'], self::MALFORMED_REQUIRE_REGISTERED],
            'a registered flag that is a word'         => [['audit-log.definitions.require_registered' => 'yes'], self::MALFORMED_REQUIRE_REGISTERED],
            'a registered flag that is a number'       => [['audit-log.definitions.require_registered' => 1], self::MALFORMED_REQUIRE_REGISTERED],
            'a source id that is not a string'         => [['audit-log.source.id' => 42], self::MALFORMED_SOURCE_ID],
            'a source id of 65 characters'             => [['audit-log.source.id' => str_repeat('s', 65)], self::MALFORMED_SOURCE_ID],
            'a source id with a control character'     => [['audit-log.source.id' => "app\x07"], self::MALFORMED_SOURCE_ID],
            'a source region that is not a string'     => [['audit-log.source.region' => 42], self::MALFORMED_SOURCE_REGION],
            'a source region of 33 characters'         => [['audit-log.source.region' => str_repeat('r', 33)], self::MALFORMED_SOURCE_REGION],
            'a source region with a control character' => [['audit-log.source.region' => "eu\x07"], self::MALFORMED_SOURCE_REGION],
            'an application name that gives no slug'   => [['app.name' => '!!!'], '[config] `audit-log.source.id` must be set, because `app.name` gives no slug.'],
            'an application name that is not a string' => [['app.name' => 42], '[config] `audit-log.source.id` must be set, because `app.name` gives no slug.'],
            'redaction keys that are a string'         => [['audit-log.redaction.keys' => 'password'], self::MALFORMED_REDACTION_KEYS],
            'redaction keys that are a map'            => [['audit-log.redaction.keys' => ['first' => 'password']], self::MALFORMED_REDACTION_KEYS],
            'redaction keys that are null'             => [['audit-log.redaction.keys' => null], self::MALFORMED_REDACTION_KEYS],
            'a redaction key name that is a number'    => [['audit-log.redaction.keys' => [42]], self::MALFORMED_REDACTION_KEYS],
            'an empty redaction key name'              => [['audit-log.redaction.keys' => ['']], self::MALFORMED_REDACTION_KEYS],
            'a redaction key name of separators'       => [['audit-log.redaction.keys' => ['_-. ']], self::MALFORMED_REDACTION_KEYS],
            'a redaction key name of invalid UTF-8'    => [['audit-log.redaction.keys' => ["pass\xFF"]], self::MALFORMED_REDACTION_KEYS],
            'a redaction key of 31 bytes'              => [['audit-log.redaction.key' => self::SHORT_SECRET], self::MALFORMED_REDACTION_KEY],
            'a redaction key that is a number'         => [['audit-log.redaction.key' => 42], self::MALFORMED_REDACTION_KEY],
            'a redaction key that does not decode'     => [['audit-log.redaction.key' => 'base64:!not-base64!'], self::MALFORMED_REDACTION_KEY],
            'a redaction key decoding to 31 bytes'     => [['audit-log.redaction.key' => 'base64:' . base64_encode(self::SHORT_SECRET)], self::MALFORMED_REDACTION_KEY],
            'a short redaction key beside a ring'      => [[...self::RING, 'audit-log.redaction.key' => self::SHORT_SECRET], self::MALFORMED_REDACTION_KEY],
            'an empty application key beside a ring'   => [[...self::RING, 'app.key' => ''], self::MISSING_APPLICATION_KEY],
            'no application key beside a ring'         => [[...self::RING, 'app.key' => null], self::MISSING_APPLICATION_KEY],
            'a numeric application key beside a ring'  => [[...self::RING, 'app.key' => 42], self::MISSING_APPLICATION_KEY],
            'a short application key beside a ring'    => [[...self::RING, 'app.key' => self::SHORT_SECRET], self::MALFORMED_APPLICATION_KEY],
            'an identifier mode that is unknown'       => [['audit-log.redaction.identifiers' => 'maybe'], self::MALFORMED_IDENTIFIERS],
            'an identifier mode in capitals'           => [['audit-log.redaction.identifiers' => 'HASH'], self::MALFORMED_IDENTIFIERS],
            'an identifier mode that is a number'      => [['audit-log.redaction.identifiers' => 1], self::MALFORMED_IDENTIFIERS],
            'an identifier mode that is null'          => [['audit-log.redaction.identifiers' => null], self::MALFORMED_IDENTIFIERS],
            'an IP mode that is unknown'               => [['audit-log.redaction.ip' => 'partial'], self::MALFORMED_IP],
            'an IP mode in capitals'                   => [['audit-log.redaction.ip' => 'FULL'], self::MALFORMED_IP],
            'an IP mode that is a number'              => [['audit-log.redaction.ip' => 1], self::MALFORMED_IP],
            'an IP mode that is null'                  => [['audit-log.redaction.ip' => null], self::MALFORMED_IP],
            'a properties budget under its minimum'    => [['audit-log.redaction.max_bytes' => 8191], self::MALFORMED_MAX_BYTES],
            'a properties budget over its ceiling'     => [['audit-log.redaction.max_bytes' => 16777217], self::MALFORMED_MAX_BYTES],
            'a properties budget that is a word'       => [['audit-log.redaction.max_bytes' => 'many'], self::MALFORMED_MAX_BYTES],
            'a properties budget that is null'         => [['audit-log.redaction.max_bytes' => null], self::MALFORMED_MAX_BYTES],
            'a context budget under its minimum'       => [['audit-log.redaction.max_context_bytes' => 1023], self::MALFORMED_MAX_CONTEXT_BYTES],
            'a context budget over its ceiling'        => [['audit-log.redaction.max_context_bytes' => 16777217], self::MALFORMED_MAX_CONTEXT_BYTES],
            'a context budget that is a word'          => [['audit-log.redaction.max_context_bytes' => 'many'], self::MALFORMED_MAX_CONTEXT_BYTES],
            'a context budget that is null'            => [['audit-log.redaction.max_context_bytes' => null], self::MALFORMED_MAX_CONTEXT_BYTES],
            'a failure mode that is unknown'           => [['audit-log.failure.mode' => 'maybe'], self::MALFORMED_FAILURE_MODE],
            'a failure mode in capitals'               => [['audit-log.failure.mode' => 'THROW'], self::MALFORMED_FAILURE_MODE],
            'a failure mode that is null'              => [['audit-log.failure.mode' => null], self::MALFORMED_FAILURE_MODE],
            'a spill channel that is a number'         => [['audit-log.failure.log_channel' => 42], self::MALFORMED_LOG_CHANNEL],
            'a spill channel of 65 characters'         => [['audit-log.failure.log_channel' => str_repeat('c', 65)], self::MALFORMED_LOG_CHANNEL],
            'a delivery mode that is unknown'          => [['audit-log.delivery.mode' => 'queue'], self::MALFORMED_DELIVERY_MODE],
            'a delivery mode that is null'             => [['audit-log.delivery.mode' => null], self::MALFORMED_DELIVERY_MODE],
            'an outbox connection that is a number'    => [
                ['audit-log.delivery.outbox.connection' => 42],
                '[config] `audit-log.delivery.outbox.connection` must be a connection name, or null or empty for the storage connection.',
            ],
            'an outbox table with a hyphen'     => [['audit-log.delivery.outbox.table' => 'audit-outbox'], self::MALFORMED_OUTBOX_TABLE],
            'an outbox table of 48 characters'  => [['audit-log.delivery.outbox.table' => str_repeat('o', 48)], self::MALFORMED_OUTBOX_TABLE],
            'a deliveries table with a hyphen'  => [['audit-log.delivery.deliveries_table' => 'audit-deliveries'], self::MALFORMED_DELIVERIES_TABLE],
            'a deliveries table that is a list' => [['audit-log.delivery.deliveries_table' => ['audit']], self::MALFORMED_DELIVERIES_TABLE],
            'a lease under its minimum'         => [
                ['audit-log.delivery.outbox.lease_seconds' => 29],
                '[config] `audit-log.delivery.outbox.lease_seconds` must be an integer from 30 to 86400.',
            ],
            'a lease over its ceiling' => [
                ['audit-log.delivery.outbox.lease_seconds' => 86401],
                '[config] `audit-log.delivery.outbox.lease_seconds` must be an integer from 30 to 86400.',
            ],
            'no attempts' => [
                ['audit-log.delivery.outbox.max_attempts' => 0],
                '[config] `audit-log.delivery.outbox.max_attempts` must be an integer from 1 to 1000.',
            ],
            'attempts over their ceiling' => [
                ['audit-log.delivery.outbox.max_attempts' => 1001],
                '[config] `audit-log.delivery.outbox.max_attempts` must be an integer from 1 to 1000.',
            ],
            'no backoff' => [
                ['audit-log.delivery.outbox.backoff_seconds' => 0],
                '[config] `audit-log.delivery.outbox.backoff_seconds` must be an integer from 1 to 3600.',
            ],
            'a backoff that is a word' => [
                ['audit-log.delivery.outbox.backoff_seconds' => 'soon'],
                '[config] `audit-log.delivery.outbox.backoff_seconds` must be an integer from 1 to 3600.',
            ],
            ...self::badIntegritySettings(),
        ];
    }

    /**
     * Each bad setting is the one problem of its run, named by its full path.
     *
     * @param  array<string, array<array-key, int|string>|int|string|null>  $settings
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideBadSettings')]
    public function testEachBadSettingIsReportedByItsFullPath(array $settings, string $problem): void
    {
        app(ConfigRepository::class)->set($settings);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([$problem], self::problemsIn($output));
    }

    /**
     * A malformed setting leaves out the subjects that depend on it.
     *
     * @return void
     */
    public function testASubjectWhoseSettingsAreMalformedIsLeftOut(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', 123);

        [, $output] = $this->check();

        self::assertSame([
            '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            '[integrity] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * A malformed storage connection is listed once, among the settings.
     *
     * @return void
     */
    public function testAMalformedStorageConnectionIsListedOnceAndFirst(): void
    {
        app(ConfigRepository::class)->set(['audit-log.storage.connection' => 123, 'audit-log.redaction.ip' => 'partial']);

        self::assertSame([
            '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            self::MALFORMED_IP,
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * A malformed maintenance connection still leaves the schema checked.
     *
     * @return void
     */
    public function testAMalformedMaintenanceConnectionStillChecksTheSchema(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', []);

        [, $output] = $this->check();

        self::assertSame([
            '[config] `audit-log.storage.maintenance_connection` must be a connection name, or null or empty for the storage connection.',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * An unconfigured storage connection is one problem; its schema is skipped.
     *
     * @return void
     */
    public function testAnUnconfiguredStorageConnectionIsNotCheckedForItsSchema(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', 'missing');

        [, $output] = $this->check();

        self::assertSame([
            '[config] OK',
            '[connections] The connection [missing] that `audit-log.storage.connection` names is not configured in `database.connections`.',
            '[integrity] OK',
            '[delivery] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * An empty storage setting checks the default connection the same way.
     *
     * @return void
     */
    public function testAnUnconfiguredDefaultConnectionIsAProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.storage.connection', '');
        $config->set('database.default', 'nowhere');

        [$code, $output] = $this->check();

        // The rollback when the test ends runs on the default connection
        $config->set('database.default', self::CONNECTION);

        self::assertSame(1, $code);
        self::assertSame([
            '[connections] The connection [nowhere] that `audit-log.storage.connection` names is not configured in `database.connections`.',
        ], self::problemsIn($output));
    }

    /**
     * A maintenance connection reaching the storage database passes.
     *
     * @return void
     */
    public function testAMaintenanceConnectionOnTheSameDriverPasses(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.maintenance', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', 'maintenance');

        // A second SQLite in-memory connection is another database: share it
        if (DB::connection(self::CONNECTION)->getDriverName() === 'sqlite') {
            DB::connection('maintenance')->setPdo(DB::connection(self::CONNECTION)->getPdo());
        }

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * The engine's problems are listed with the tables'.
     *
     * @return void
     */
    public function testTheEnginesProblemsAreListedWithTheTables(): void
    {
        $schema = \Mockery::mock(MySqlBuilder::class);

        $schema->shouldReceive('hasTable')->andReturnFalse();

        $connection = \Mockery::mock(MySqlConnection::class . '[getSchemaBuilder,scalar]', [new VersionReportingPdo('8.4.11'), '', '', ['driver' => 'mysql', 'name' => 'fake']]);

        $connection->shouldReceive('getSchemaBuilder')->andReturn($schema);
        $connection->shouldReceive('scalar')->andReturnUsing(static fn (string $query): string => str_contains($query, 'sql_mode') ? 'NO_ENGINE_SUBSTITUTION' : 'InnoDB');

        $config = app(ConfigRepository::class);

        $config->set('database.connections.fake', ['driver' => 'mysql', 'database' => ':memory:', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'fake');

        $this->app?->make(DatabaseManager::class)->extend('fake', static fn (): MySqlConnection => $connection);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[schema] The storage connection does not run in strict mode; set `strict` to true on the connection, so a value that does not fit fails instead of'
                . ' being cut.',
            '[schema] The entries table `audit_log_entries` does not exist on connection [fake]' . self::PUBLISH,
            '[schema] The artifacts table `audit_log_artifacts` does not exist on connection [fake]' . self::PUBLISH,
            '[integrity] The checkpoints table `audit_log_checkpoints` does not exist on connection [fake]' . self::PUBLISH,
            '[integrity] The checkpoint members table `audit_log_checkpoint_members` does not exist on connection [fake]' . self::PUBLISH,
            '[integrity] The integrity state table `audit_log_integrity_state` does not exist on connection [fake]' . self::PUBLISH,
            '[lifecycle] The lifecycle journal table `audit_log_lifecycle` does not exist on connection [fake]' . self::PUBLISH,
            '[lifecycle] The holds table `audit_log_holds` does not exist on connection [fake]' . self::PUBLISH,
            '[lifecycle] The lifecycle lock table `audit_log_lifecycle_lock` does not exist on connection [fake]' . self::PUBLISH,
            '[lifecycle] The import batches table `audit_log_import_batches` does not exist on connection [fake]' . self::PUBLISH,
            '[privacy] The subject keys table `audit_log_subject_keys` does not exist on connection [fake]' . self::PUBLISH,
            '[privacy] The owner erasures table `audit_log_owner_erasures` does not exist on connection [fake]' . self::PUBLISH,
            '[privacy] The key uses table `audit_log_key_uses` does not exist on connection [fake]' . self::PUBLISH,
        ], self::problemsIn($output));
    }

    /**
     * A missing entries table is one problem, not one per column and index.
     *
     * @return void
     */
    public function testAMissingTableIsReportedOnce(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', self::ABSENT_TABLE);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] The entries table `audit_absent_entries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * A missing artifacts table is one schema problem after the entries'.
     *
     * @return void
     */
    public function testAMissingArtifactsTableFailsTheSchemaSubject(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.artifacts_table', self::ABSENT_ARTIFACTS_TABLE);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] The artifacts table `audit_absent_artifacts` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * Missing entries and artifacts tables are each a problem, entries first.
     *
     * @return void
     */
    public function testMissingEntriesAndArtifactsTablesAreEachAProblem(): void
    {
        app(ConfigRepository::class)->set(['audit-log.entries.table' => self::ABSENT_TABLE, 'audit-log.entries.artifacts_table' => self::ABSENT_ARTIFACTS_TABLE]);

        self::assertSame([
            '[schema] The entries table `audit_absent_entries` does not exist on connection [testing]' . self::PUBLISH,
            '[schema] The artifacts table `audit_absent_artifacts` does not exist on connection [testing]' . self::PUBLISH,
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * Each missing and extra artifacts column is a schema problem.
     *
     * @return void
     */
    public function testAnArtifactsTableOfTheWrongShapeFailsTheSchemaSubject(): void
    {
        Schema::table('audit_log_artifacts', static function (Blueprint $table): void {
            $table->dropColumn('digest');
        });

        Schema::table('audit_log_artifacts', static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[schema] Column `digest` is missing.',
            '[schema] Column `notes` is not one the package writes.',
        ], self::problemsIn($output));
    }

    /**
     * A malformed artifacts table name still leaves the entries table checked.
     *
     * @return void
     */
    public function testAMalformedArtifactsTableNameLeavesTheEntriesTableChecked(): void
    {
        app(ConfigRepository::class)->set(['audit-log.entries.table' => self::ABSENT_TABLE, 'audit-log.entries.artifacts_table' => 'audit-artifacts']);

        self::assertSame([
            '[config] `audit-log.entries.artifacts_table` must be a table name of 1 to 47 lower-case letters, digits and underscores'
                . ' that does not start with a digit.',
            '[schema] The entries table `audit_absent_entries` does not exist on connection [testing]' . self::PUBLISH,
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * Every problem across subjects is listed by one run, in subject order.
     *
     * @return void
     */
    public function testEveryProblemIsListedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.storage.maintenance_connection', 'missing');
        $config->set('audit-log.integrity.keys', 'x');

        Schema::table('audit_log_entries', static function (Blueprint $table): void {
            $table->dropColumn('reason');
            $table->string('notes')->nullable();
        });

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] `audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.',
            '[connections] The connection [missing] that `audit-log.storage.maintenance_connection` names is not configured in `database.connections`.',
            '[schema] Column `reason` is missing.',
            '[schema] Column `notes` is not one the package writes, so no entry\'s HMAC covers it.',
            '[delivery] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * No secret, application key, statement or binding is ever printed.
     *
     * @return void
     */
    public function testNoSecretOrBindingIsPrinted(): void
    {
        $path = $this->garbageFile();

        $config = app(ConfigRepository::class);
        $secret = 'base64:' . base64_encode(self::SHORT_SECRET);

        $config->set('database.connections.garbage', ['driver' => 'sqlite', 'database' => $path, 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'garbage');
        $config->set('audit-log.integrity.keys', ['k1' => $secret]);
        $config->set('audit-log.integrity.current', 'k1');

        [$code, $output] = $this->check();

        $printed = implode("\n", $output);

        self::assertSame(1, $code);
        self::assertSame([
            '[config] `audit-log.integrity.keys.k1` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.',
            '[connections] OK',
            '[schema] The storage connection [garbage] could not be read (Illuminate\Database\QueryException).',
            '[delivery] OK',
            self::SPILL_NOTE,
        ], $output);

        foreach ([self::SHORT_SECRET, $secret, $config->string('app.key'), $path, 'select', 'sqlite_master', 'SQL'] as $hidden) {
            self::assertStringNotContainsString($hidden, $printed);
        }
    }

    /**
     * An unreachable connection is a problem named by its exception class.
     *
     * @return void
     */
    public function testAnUnreachableConnectionIsAProblemNotACrash(): void
    {
        $path   = sys_get_temp_dir() . '/audit-log-missing-' . getmypid() . '.sqlite';
        $config = app(ConfigRepository::class);

        $config->set('database.connections.broken', ['driver' => 'sqlite', 'database' => $path, 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'broken');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] The storage connection [broken] could not be opened (' . SQLiteDatabaseDoesNotExistException::class . ').',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
        self::assertStringNotContainsString($path, implode("\n", $output));
    }

    /**
     * A guard not in `auth.guards` is the one problem of its run.
     *
     * @return void
     */
    public function testAGuardNotInAuthGuardsIsAProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', ['web', 'missing']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] The guard [missing] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * Each missing guard is listed once, in the list's order.
     *
     * @return void
     */
    public function testEveryMissingGuardIsListedOnceInOrder(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', ['second', 'web', 'first', 'second']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] The guard [second] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            '[config] The guard [first] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
        ], self::problemsIn($output));
    }

    /**
     * With no guard list, a default guard `auth.guards` lacks is a problem.
     *
     * @return void
     */
    public function testADefaultGuardNotInAuthGuardsIsAProblem(): void
    {
        app(ConfigRepository::class)->set('auth.defaults.guard', 'nowhere');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] The default guard [nowhere] is not configured in `auth.guards`, and the actor is read from it.',
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * Rows of `[the settings changed, how the default guard is named]`.
     *
     * @return iterable<string, array{0: array<string, array<array-key, array<string, string>|string>|string|null>, 1: string}>
     */
    public static function provideUnusableDefaultGuards(): iterable
    {
        yield from [
            'no default guard'                     => [['auth.defaults.guard' => null], 'null'],
            'a default guard that is not a name'   => [['auth.defaults.guard' => ['web']], 'array'],
            'an empty default guard'               => [['auth.defaults.guard' => ''], ''],
            'a guard configured as a string'       => [['auth.guards' => ['web' => 'session']], 'web'],
            'no guards at all'                     => [['auth.guards' => null], 'web'],
            'a dotted name AuthManager cannot see' => [['auth.defaults.guard' => 'api.v1', 'auth.guards' => ['api.v1' => ['driver' => 'session']]], 'api.v1'],
        ];
    }

    /**
     * An unresolvable default guard is the one problem of its run.
     *
     * @param  array<string, array<array-key, array<string, string>|string>|string|null>  $settings
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideUnusableDefaultGuards')]
    public function testAnUnusableDefaultGuardIsAProblem(array $settings, string $name): void
    {
        app(ConfigRepository::class)->set($settings);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([sprintf('[config] The default guard [%s] is not configured in `auth.guards`, and the actor is read from it.', $name)], self::problemsIn($output));
    }

    /**
     * A configured guard list passes and the default guard is not checked.
     *
     * @return void
     */
    public function testAConfiguredGuardListPasses(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users']);
        $config->set('auth.defaults.guard', 'nowhere');
        $config->set('audit-log.actor.guards', ['api', 'web']);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * A malformed guard list is reported once, without the default guard.
     *
     * @return void
     */
    public function testAMalformedGuardListIsReportedOnce(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.actor.guards', 'web');
        $config->set('auth.defaults.guard', 'nowhere');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([self::MALFORMED_GUARDS], self::problemsIn($output));
    }

    /**
     * Every value at the edge of what a new setting accepts passes. A source id
     * that is no log id needs a log id of its own.
     *
     * @return void
     */
    public function testTheNewSettingsAcceptEveryGoodValue(): void
    {
        $config = app(ConfigRepository::class);
        $guard  = str_repeat('g', 64);

        $config->set('audit-log.integrity.log_id', 'app-eu-1');

        $config->set("auth.guards.{$guard}", ['driver' => 'session', 'provider' => 'users']);
        $config->set('audit-log.actor.guards', [$guard]);
        $config->set('audit-log.context.trust_request_id', true);
        $config->set('audit-log.context.request_id_header', str_repeat('h', 64));
        $config->set('audit-log.context.trust_traceparent', false);
        $config->set('audit-log.definitions.require_registered', true);
        $config->set('audit-log.source.id', str_repeat('é', 64));
        $config->set('audit-log.source.region', str_repeat('é', 32));
        $config->set('audit-log.redaction.keys', ['internalNote', 'x', 'é']);
        $config->set('audit-log.redaction.key', str_repeat('k', 32));
        $config->set('audit-log.redaction.identifiers', 'drop');
        $config->set('audit-log.redaction.ip', 'truncate');
        $config->set('audit-log.redaction.max_bytes', 8192);
        $config->set('audit-log.redaction.max_context_bytes', 1024);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.source.id', '');
        $config->set('audit-log.source.region', '');
        $config->set('audit-log.redaction.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $config->set('audit-log.redaction.identifiers', 'hash');
        $config->set('audit-log.redaction.ip', 'hash');
        $config->set('audit-log.redaction.max_bytes', 16777216);
        $config->set('audit-log.redaction.max_context_bytes', 16777216);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.redaction.key', '');
        $config->set('audit-log.redaction.ip', 'drop');
        $config->set('audit-log.redaction.max_bytes', '8192');
        $config->set('audit-log.redaction.max_context_bytes', '1024');

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.redaction.ip', 'encrypt');

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * The shipped defaults of the new settings pass.
     *
     * @return void
     */
    public function testTheShippedDefaultsOfTheNewSettingsPass(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.actor.guards'                   => null,
            'audit-log.context.trust_request_id'       => false,
            'audit-log.context.request_id_header'      => 'X-Request-Id',
            'audit-log.context.trust_traceparent'      => false,
            'audit-log.definitions.require_registered' => false,
            'audit-log.source.id'                      => null,
            'audit-log.source.region'                  => null,
            'audit-log.redaction.keys'                 => [],
            'audit-log.redaction.key'                  => null,
            'audit-log.redaction.identifiers'          => 'hash',
            'audit-log.redaction.ip'                   => 'full',
            'audit-log.redaction.max_bytes'            => 16384,
            'audit-log.redaction.max_context_bytes'    => 4096,
        ]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * Each new settings group reports in one run, leaving out no later subject.
     *
     * @return void
     */
    public function testEveryNewSettingProblemIsListedAndNoSubjectIsLeftOut(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.actor.guards'                   => ['missing'],
            'audit-log.context.trust_traceparent'      => 'yes',
            'audit-log.definitions.require_registered' => 'yes',
            'audit-log.entries.table'                  => self::ABSENT_TABLE,
            'audit-log.source.region'                  => 42,
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            self::MALFORMED_TRUST_TRACEPARENT,
            self::MALFORMED_SOURCE_REGION,
            self::MALFORMED_REQUIRE_REGISTERED,
            '[config] The guard [missing] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            '[connections] OK',
            '[schema] The entries table `audit_absent_entries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * Every malformed new setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedNewLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.actor.guards', 'web');
        $config->set('audit-log.context.trust_request_id', 'yes');
        $config->set('audit-log.context.request_id_header', 'X Request');
        $config->set('audit-log.context.trust_traceparent', 'yes');
        $config->set('audit-log.source.id', 42);
        $config->set('audit-log.source.region', 42);
        $config->set('audit-log.definitions.require_registered', '1');

        self::assertSame([
            '[config] `audit-log.source.id` must be from 1 to 64 characters, with no control characters.',
            '[config] `audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.',
            self::MALFORMED_TRUST_REQUEST_ID,
            '[config] `audit-log.context.request_id_header` must be a header name of 1 to 64 characters.',
            self::MALFORMED_TRUST_TRACEPARENT,
            '[config] `audit-log.source.region` must be null or empty, or from 1 to 32 characters, with no control characters.',
            '[config] `audit-log.definitions.require_registered` must be true or false.',
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * A malformed key id and ring are each listed; a ring reads no `app.key`.
     *
     * @return void
     */
    public function testEveryMalformedIntegritySettingIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('app.key', 'not a key');
        $config->set('audit-log.integrity.current', 42);
        $config->set('audit-log.integrity.keys', 'x');

        $problems = self::problemsIn($this->check()[1]);

        self::assertCount(2, $problems);
        self::assertStringContainsString('`audit-log.integrity.current`', $problems[0]);
        self::assertStringContainsString('`audit-log.integrity.keys`', $problems[1]);
    }

    /**
     * Without a ring, a malformed `app.key` is listed with a malformed key id.
     *
     * @return void
     */
    public function testAMalformedApplicationKeyIsListedWithACurrentKeyId(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('app.key', '');
        $config->set('audit-log.integrity.current', 'k1');

        self::assertCount(2, self::problemsIn($this->check()[1]));
    }

    /**
     * Without a ring, a bad `app.key` is one line from the integrity settings.
     *
     * @return void
     */
    public function testAnApplicationKeyIsReportedOnceWithoutARing(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('app.key', '');

        self::assertSame([self::MISSING_INTEGRITY_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set('app.key', self::SHORT_SECRET);

        self::assertSame([self::MALFORMED_INTEGRITY_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set('audit-log.integrity.keys', []);

        self::assertSame([self::MALFORMED_INTEGRITY_APPLICATION_KEY], self::problemsIn($this->check()[1]));
    }

    /**
     * With a ring, an empty redaction key names `app.key` and integrity passes.
     *
     * @return void
     */
    public function testTheRedactionKeyFallsToTheApplicationKeyWithARing(): void
    {
        app(ConfigRepository::class)->set([...self::RING, 'audit-log.redaction.key' => '', 'app.key' => '']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([self::MISSING_APPLICATION_KEY, '[connections] OK', '[schema] OK', '[integrity] OK', '[delivery] OK', '[lifecycle] OK', self::SPILL_NOTE], $output);
    }

    /**
     * A ring beside a good `app.key` in either key form passes.
     *
     * @return void
     */
    public function testARingAndAGoodApplicationKeyPass(): void
    {
        $config = app(ConfigRepository::class);

        $config->set([...self::RING, 'app.key' => str_repeat('k', 32)]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * An explicit redaction key is the root secret, so it needs no `app.key`.
     *
     * @return void
     */
    public function testAnExplicitRedactionKeyNeedsNoApplicationKey(): void
    {
        $config = app(ConfigRepository::class);

        $config->set([...self::RING, 'audit-log.redaction.key' => str_repeat('k', 32), 'app.key' => '']);

        self::assertSame([self::MALFORMED_WRAPPING_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set(self::WRAPPING_RING);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.integrity.keys', []);
        $config->set('audit-log.integrity.current', null);

        self::assertSame([self::MISSING_INTEGRITY_APPLICATION_KEY], self::problemsIn($this->check()[1]));
    }

    /**
     * A malformed explicit redaction key never falls back to `app.key`.
     *
     * @return void
     */
    public function testAMalformedRedactionKeyHidesTheApplicationKeyBesideARing(): void
    {
        $config = app(ConfigRepository::class);

        $config->set([...self::RING, 'audit-log.redaction.key' => 'short', 'app.key' => '']);

        self::assertSame([self::MALFORMED_REDACTION_KEY, self::MALFORMED_WRAPPING_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set(self::WRAPPING_RING);

        self::assertSame([self::MALFORMED_REDACTION_KEY], self::problemsIn($this->check()[1]));
    }

    /**
     * Rows of `[the settings changed, the one problem]`: unreadable rings.
     *
     * @return iterable<string, array{0: array<string, array<string, string>|string>, 1: string}>
     */
    public static function provideMalformedRings(): iterable
    {
        yield from [
            'a ring that is not a map' => [
                ['audit-log.integrity.keys' => 'x'],
                '[config] `audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.',
            ],
            'a ring with a short secret' => [
                ['audit-log.integrity.keys' => ['k1' => self::SHORT_SECRET], 'audit-log.integrity.current' => 'k1'],
                '[config] `audit-log.integrity.keys.k1` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.',
            ],
        ];
    }

    /**
     * A malformed ring is listed once and `app.key` is not read.
     *
     * @param  array<string, array<string, string>|string>  $settings
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideMalformedRings')]
    public function testAMalformedRingIsListedOnce(array $settings, string $problem): void
    {
        app(ConfigRepository::class)->set([...$settings, 'app.key' => '']);

        self::assertSame([$problem], self::problemsIn($this->check()[1]));
    }

    /**
     * Every malformed redaction setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedRedactionLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.redaction.max_context_bytes', 1023);
        $config->set('audit-log.redaction.max_bytes', 8191);
        $config->set('audit-log.redaction.key', 'short');
        $config->set('audit-log.redaction.ip', 'partial');
        $config->set('audit-log.redaction.identifiers', 'maybe');
        $config->set('audit-log.redaction.keys', 'password');

        $malformed = [
            self::MALFORMED_REDACTION_KEYS,
            self::MALFORMED_IDENTIFIERS,
            self::MALFORMED_IP,
            self::MALFORMED_MAX_BYTES,
            self::MALFORMED_MAX_CONTEXT_BYTES,
        ];

        self::assertSame([...$malformed, self::MALFORMED_REDACTION_KEY], self::problemsIn($this->check()[1]));

        $config->set([...self::RING, 'audit-log.redaction.key' => null, 'app.key' => self::SHORT_SECRET]);

        self::assertSame([...$malformed, self::MALFORMED_APPLICATION_KEY], self::problemsIn($this->check()[1]));
    }

    /**
     * A malformed redaction setting reports after the guards, skipping nothing.
     *
     * @return void
     */
    public function testAMalformedRedactionSettingLeavesOutNoSubject(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.actor.guards'  => ['missing'],
            'audit-log.source.region' => 42,
            'audit-log.redaction.ip'  => 'partial',
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            self::MALFORMED_SOURCE_REGION,
            '[config] The guard [missing] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            self::MALFORMED_IP,
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * A missing integrity table is an integrity problem; other subjects pass.
     *
     * @return void
     */
    public function testAMissingIntegrityTableIsAnIntegrityProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.members_table', 'audit_absent_members');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] OK',
            '[integrity] The checkpoint members table `audit_absent_members` does not exist on connection [testing]' . self::PUBLISH,
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * An unconfigured anchor disk is a problem and is never resolved.
     *
     * @return void
     */
    public function testAnUnconfiguredAnchorDiskIsAProblem(): void
    {
        $filesystems = app('filesystem');
        $spy         = \Mockery::mock(Factory::class);

        $spy->shouldReceive('disk')->never();

        $this->app?->instance(Factory::class, $spy);
        $this->app?->instance('filesystem', $spy);

        $config = app(ConfigRepository::class);

        $config->set(['audit-log.integrity.anchor.driver' => 'disk', 'audit-log.integrity.anchor.disk' => 'anchors']);

        $unconfigured = ['[config] OK', '[connections] OK', '[schema] OK', self::UNCONFIGURED_DISK, '[delivery] OK', '[lifecycle] OK', '[privacy] OK', self::SPILL_NOTE];

        self::assertSame([1, $unconfigured], $this->check());

        // A root no other run anchors to, so the head read is this log's
        $root = sys_get_temp_dir() . '/audit-log-anchors-' . getmypid() . '-' . hrtime(true);

        $config->set('filesystems.disks.anchors', ['driver' => 'local', 'root' => $root]);

        $this->app?->instance(Factory::class, $filesystems);
        $this->app?->instance('filesystem', $filesystems);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        if (!is_dir($root)) {
            return;
        }

        rmdir($root);
    }

    /**
     * With no anchor configured, an unconfigured disk setting passes.
     *
     * @return void
     */
    public function testTheNullAnchorNeedsNoDisk(): void
    {
        app(ConfigRepository::class)->set(['audit-log.integrity.anchor.driver' => null, 'audit-log.integrity.anchor.disk' => 'anchors']);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A malformed seal setting skips the integrity tables and the disk.
     *
     * @return void
     */
    public function testAMalformedSealSettingSkipsTheIntegrityTables(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.integrity.seal.batch'    => 99,
            'audit-log.integrity.members_table' => 'audit_absent_members',
            'audit-log.integrity.anchor.driver' => 'disk',
            'audit-log.integrity.anchor.disk'   => 'anchors',
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] `audit-log.integrity.seal.batch` must be an integer from 100 to 50000.',
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * A malformed storage connection leaves the integrity tables unchecked.
     *
     * @return void
     */
    public function testAMalformedStorageConnectionSkipsTheIntegrityTables(): void
    {
        app(ConfigRepository::class)->set(['audit-log.storage.connection' => 123, 'audit-log.integrity.members_table' => 'audit_absent_members']);

        self::assertSame([
            1,
            ['[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.', '[integrity] OK', self::SPILL_NOTE],
        ], $this->check());
    }

    /**
     * A malformed integrity key setting leaves the subject out altogether.
     *
     * @return void
     */
    public function testAMalformedKeySettingLeavesTheIntegrityTablesOut(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.integrity.keys'          => 'x',
            'audit-log.integrity.members_table' => 'audit_absent_members',
        ]);

        [, $output] = $this->check();

        self::assertSame(['[config] `audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.'], self::problemsIn($output));
        self::assertNotContains('[integrity] OK', $output);
    }

    /**
     * Every malformed integrity setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedIntegrityLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        foreach (array_reverse(self::BAD_LEAVES, true) as $leaf => $bad) {

            if (!str_starts_with($leaf, 'integrity.') || in_array($leaf, ['integrity.keys', 'integrity.current'], true)) {
                continue;
            }

            $config->set("audit-log.{$leaf}", $bad);
        }

        $table = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';
        $cron  = ' must be a cron expression, or null or empty to schedule nothing.';

        self::assertSame([
            self::MALFORMED_LOG_ID,
            '[config] `audit-log.integrity.checkpoints_table`' . $table,
            '[config] `audit-log.integrity.members_table`' . $table,
            '[config] `audit-log.integrity.state_table`' . $table,
            '[config] `audit-log.integrity.seal.batch` must be an integer from 100 to 50000.',
            '[config] `audit-log.integrity.seal.max_batches` must be an integer from 1 to 100000.',
            '[config] `audit-log.integrity.seal.lookback_seconds` must be an integer from 0 to 2592000.',
            '[config] `audit-log.integrity.seal.settle_seconds` must be an integer from 0 to 3600.',
            '[config] `audit-log.integrity.seal.max_attempts` must be an integer from 1 to 100.',
            '[config] `audit-log.integrity.verify.max_unsealed_age_seconds` must be an integer from 600 to 31536000.',
            '[config] `audit-log.integrity.seal.schedule`' . $cron,
            '[config] `audit-log.integrity.seal.sweep_schedule`' . $cron,
            '[config] `audit-log.integrity.verify.schedule`' . $cron,
            '[config] `audit-log.integrity.anchor.driver` must be `null` or `disk`.',
            '[config] `audit-log.integrity.anchor.disk` must be a disk name of 1 to 64 characters, or null or empty for the default disk.',
            '[config] `audit-log.integrity.anchor.path` must be 1 to 191 characters of path segments of letters, digits, dots, underscores and hyphens,'
                . ' separated by single slashes, with no `.` or `..` segment.',
            '[config] `audit-log.integrity.anchor.batch` must be an integer from 1 to 10000.',
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]` for integrity.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function provideIntegrityValuesThatMustNotBePrinted(): iterable
    {
        $long = str_repeat(self::SENTINEL, 8);

        yield from [
            'a log id'                      => ['audit-log.integrity.log_id', self::SENTINEL . '/x', self::SENTINEL],
            'a log id that is a list'       => ['audit-log.integrity.log_id', [self::SENTINEL], self::SENTINEL],
            'a source id that is no log id' => ['audit-log.source.id', self::SENTINEL . ' x', self::SENTINEL],
            'a checkpoints table'           => ['audit-log.integrity.checkpoints_table', self::SENTINEL, self::SENTINEL],
            'a members table'               => ['audit-log.integrity.members_table', self::SENTINEL, self::SENTINEL],
            'a state table'                 => ['audit-log.integrity.state_table', self::SENTINEL, self::SENTINEL],
            'a sealing schedule'            => ['audit-log.integrity.seal.schedule', self::SENTINEL, self::SENTINEL],
            'a sweep schedule'              => ['audit-log.integrity.seal.sweep_schedule', self::SENTINEL, self::SENTINEL],
            'a verification schedule'       => ['audit-log.integrity.verify.schedule', [self::SENTINEL], self::SENTINEL],
            'a batch'                       => ['audit-log.integrity.seal.batch', self::SENTINEL, self::SENTINEL],
            'a number of batches'           => ['audit-log.integrity.seal.max_batches', self::SENTINEL, self::SENTINEL],
            'a lookback'                    => ['audit-log.integrity.seal.lookback_seconds', self::SENTINEL, self::SENTINEL],
            'a settle'                      => ['audit-log.integrity.seal.settle_seconds', self::SENTINEL, self::SENTINEL],
            'a number of seal attempts'     => ['audit-log.integrity.seal.max_attempts', self::SENTINEL, self::SENTINEL],
            'an overdue age'                => ['audit-log.integrity.verify.max_unsealed_age_seconds', self::SENTINEL, self::SENTINEL],
            'an anchor driver'              => ['audit-log.integrity.anchor.driver', self::SENTINEL, self::SENTINEL],
            'an anchor disk too long'       => ['audit-log.integrity.anchor.disk', $long, self::SENTINEL],
            'an anchor disk that is a list' => ['audit-log.integrity.anchor.disk', [self::SENTINEL], self::SENTINEL],
            'an anchor path'                => ['audit-log.integrity.anchor.path', '../' . self::SENTINEL, self::SENTINEL],
            'an anchor batch'               => ['audit-log.integrity.anchor.batch', self::SENTINEL, self::SENTINEL],
        ];
    }

    /**
     * A bad integrity setting fails the run and its value is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideIntegrityValuesThatMustNotBePrinted')]
    public function testThePrintedOutputHoldsNoValueOfAnIntegritySetting(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * Every configuration leaf has a check; a new leaf without one fails here.
     *
     * @return void
     */
    public function testEveryNewLeafIsCoveredByACheck(): void
    {
        $config   = app(ConfigRepository::class);
        $settings = $config->array('audit-log');
        $leaves   = self::leavesOf($settings);

        self::assertContains('storage.connection', $leaves);
        self::assertContains('integrity.keys', $leaves);
        self::assertSame([], array_values(array_diff($leaves, array_keys(self::BAD_LEAVES))), 'A leaf of the configuration has no bad value, so no check is known to cover it.');

        foreach (self::BAD_LEAVES as $leaf => $bad) {

            $config->set("audit-log.{$leaf}", $bad);

            [$code, $output] = $this->check();

            $config->set('audit-log', $settings);

            $named = array_filter($output, static fn (string $line): bool => str_starts_with($line, "[config] `audit-log.{$leaf}` "));

            self::assertSame(1, $code, "A bad `{$leaf}` must fail the run.");
            self::assertCount(1, $named, "A bad `{$leaf}` must be named by one `[config]` line.");
        }

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * The walk finds leaves at any depth, so the coverage test is not vacuous.
     *
     * @return void
     */
    public function testTheWalkFindsEveryLeaf(): void
    {
        self::assertSame(
            ['top.deep.leaf', 'top.empty', 'top.list', 'unset', 'plain'],
            self::leavesOf(['top' => ['deep' => ['leaf' => 1], 'empty' => [], 'list' => ['a', 'b']], 'unset' => null, 'plain' => 'value']),
        );
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]`.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function provideValuesThatMustNotBePrinted(): iterable
    {
        $long = str_repeat(self::SENTINEL, 8);

        yield from [
            'guards that are a string'                 => ['audit-log.actor.guards', self::SENTINEL, self::SENTINEL],
            'guards that are a map'                    => ['audit-log.actor.guards', [self::SENTINEL => self::SENTINEL], self::SENTINEL],
            'a guard name too long'                    => ['audit-log.actor.guards', [$long], self::SENTINEL],
            'a guard name with a control character'    => ['audit-log.actor.guards', [self::SENTINEL . "\x07"], self::SENTINEL],
            'a request id flag'                        => ['audit-log.context.trust_request_id', self::SENTINEL, self::SENTINEL],
            'a header name'                            => ['audit-log.context.request_id_header', self::SENTINEL . ' X', self::SENTINEL],
            'a traceparent flag'                       => ['audit-log.context.trust_traceparent', self::SENTINEL, self::SENTINEL],
            'a registered flag'                        => ['audit-log.definitions.require_registered', self::SENTINEL, self::SENTINEL],
            'a source id too long'                     => ['audit-log.source.id', $long, self::SENTINEL],
            'a source id with a control character'     => ['audit-log.source.id', self::SENTINEL . "\x07", self::SENTINEL],
            'a source region too long'                 => ['audit-log.source.region', $long, self::SENTINEL],
            'a source region with a control character' => ['audit-log.source.region', self::SENTINEL . "\x07", self::SENTINEL],
            'an application name that gives no slug'   => ['app.name', '!~!~!~', '!~!~!~'],
            'an application name that is not a string' => ['app.name', [self::SENTINEL], self::SENTINEL],
            'a default guard that is not a name'       => ['auth.defaults.guard', [self::SENTINEL], self::SENTINEL],
            'redaction keys that are a string'         => ['audit-log.redaction.keys', self::SENTINEL, self::SENTINEL],
            'redaction keys that are a map'            => ['audit-log.redaction.keys', [self::SENTINEL => self::SENTINEL], self::SENTINEL],
            'a redaction key name of invalid UTF-8'    => ['audit-log.redaction.keys', [self::SENTINEL . "\xFF"], self::SENTINEL],
            'a redaction key too short'                => ['audit-log.redaction.key', self::SENTINEL, self::SENTINEL],
            'a redaction key that does not decode'     => ['audit-log.redaction.key', 'base64:' . self::SENTINEL, self::SENTINEL],
            'a redaction key decoding too short'       => ['audit-log.redaction.key', 'base64:' . base64_encode(self::SENTINEL), base64_encode(self::SENTINEL)],
            'an identifier mode'                       => ['audit-log.redaction.identifiers', self::SENTINEL, self::SENTINEL],
            'an IP mode'                               => ['audit-log.redaction.ip', self::SENTINEL, self::SENTINEL],
            'a properties budget'                      => ['audit-log.redaction.max_bytes', self::SENTINEL, self::SENTINEL],
            'a context budget'                         => ['audit-log.redaction.max_context_bytes', self::SENTINEL, self::SENTINEL],
        ];
    }

    /**
     * A bad setting value fails the run and is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideValuesThatMustNotBePrinted')]
    public function testNoSettingValueIsPrinted(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertNotSame([], self::problemsIn($output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * Rows of `[settings beside the application key]`: with and without a ring.
     *
     * @return iterable<string, array{0: array<string, array<string, string>|string>}>
     */
    public static function provideRingSettings(): iterable
    {
        yield from [
            'without a ring' => [[]],
            'beside a ring'  => [self::RING],
        ];
    }

    /**
     * A short `app.key` or a ring's secret fails the run and is never printed.
     *
     * @param  array<string, array<string, string>|string>  $settings
     * @return void
     */
    #[DataProvider('provideRingSettings')]
    public function testNoApplicationKeyIsPrinted(array $settings): void
    {
        app(ConfigRepository::class)->set([...$settings, 'app.key' => self::SENTINEL]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringNotContainsString(self::SENTINEL, implode("\n", $output));
        self::assertStringNotContainsString('a-secret-of-exactly-32-bytes-ok!', implode("\n", $output));
    }

    /**
     * Two runs write nothing to the entries, lifecycle or integrity state.
     *
     * @return void
     */
    public function testTheCheckWritesNothing(): void
    {
        $tables = [
            'audit_log_entries', 'audit_log_lifecycle', 'audit_log_holds', 'audit_log_import_batches', 'audit_log_checkpoints',
            'audit_log_subject_keys', 'audit_log_owner_erasures', 'audit_log_key_uses',
        ];
        $counts = static fn (): array => array_map(static fn (string $table): int => DB::table($table)->count(), $tables);
        $before = $counts();
        $state  = DB::table('audit_log_integrity_state')->get()->all();

        self::assertSame([InstallationIdentity::NAME], array_column($state, 'name'));

        $this->check();
        $this->check();

        self::assertSame([0, 0, 0, 0, 0, 0, 0, 0], $before);
        self::assertSame($before, $counts());
        self::assertEquals($state, DB::table('audit_log_integrity_state')->get()->all());
        $rows = DB::table('audit_log_lifecycle_lock')->get()->all();
        $lock = array_map(static fn (object $row): array => ['id' => (int) $row->id, 'token' => $row->token, 'locked_at' => $row->locked_at], $rows);

        self::assertSame([['id' => 1, 'token' => null, 'locked_at' => null]], $lock);
    }

    /**
     * A missing installation id fails the run and is not written.
     *
     * @return void
     */
    public function testAMissingInstallationIdFailsTheRunAndIsNotWritten(): void
    {
        DB::table('audit_log_integrity_state')->delete();

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[lifecycle] The storage connection reaches no installation id; the package\'s migrations seed it, and `audit-log:seal` writes it when it is missing.',
        ], self::problemsIn($output));
        self::assertSame(0, DB::table('audit_log_integrity_state')->count());
    }

    /**
     * The lifecycle subject follows `delivery`; a problem there fails the run.
     *
     * @return void
     */
    public function testTheLifecycleSubjectIsListed(): void
    {
        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(['[delivery] OK', '[lifecycle] OK'], array_slice($output, 4, 2));

        DB::table('audit_log_lifecycle_lock')->delete();

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame(['[lifecycle] The lifecycle lock row is missing; run the migrations, which seed it.'], self::problemsIn($output));
        self::assertSame('[lifecycle] The lifecycle lock row is missing; run the migrations, which seed it.', $output[5]);
    }

    /**
     * Only a malformed lifecycle table name leaves the lifecycle subject out.
     *
     * @return void
     */
    public function testAMalformedLifecycleTableLeavesTheSubjectOut(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.lifecycle.holds_table', 'audit-holds');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertNotContains('[lifecycle] OK', $output);
        self::assertSame([], array_values(array_filter($output, static fn (string $line): bool => str_starts_with($line, '[lifecycle]'))));

        $config->set('audit-log.lifecycle.holds_table', 'audit_log_holds');
        $config->set('audit-log.import.chunk', 99);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[lifecycle] OK', $output);
    }

    /**
     * The privacy subject follows `lifecycle`; a problem there fails the run.
     *
     * @return void
     */
    public function testThePrivacySubjectIsChecked(): void
    {
        $missing = '[privacy] The key uses table `audit_absent_key_uses` does not exist on connection [testing]' . self::PUBLISH;
        $config  = app(ConfigRepository::class);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(['[lifecycle] OK', '[privacy] OK'], array_slice($output, 5, 2));

        $config->set('audit-log.privacy.key_uses_table', 'audit_absent_key_uses');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([$missing], self::problemsIn($output));
        self::assertSame($missing, $output[6]);

        $config->set('audit-log.privacy.rewrap_batch', 99);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame(['[config] `audit-log.privacy.rewrap_batch` must be an integer from 100 to 10000.'], self::problemsIn($output));
        self::assertSame([], array_values(array_filter($output, static fn (string $line): bool => str_starts_with($line, '[privacy]'))));
    }

    /**
     * A database restored behind its anchor fails the run until reconciled.
     *
     * @return void
     */
    public function testARestoredDatabaseExitsNonZero(): void
    {
        $digest = str_repeat('d', 64);

        $this->app?->instance(CheckpointAnchor::class, (new RecordingAnchor)->holdInstead(3, $digest));

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[privacy] The database does not hold the seal its anchor holds at sequence 3, so it was restored from a backup or rewritten; re-apply every'
                . ' erasure since with `audit-log:erase --reapply=<file>`, which reconciles the restore, and run `audit-log:verify`.',
        ], self::problemsIn($output));

        $this->journalRow(JournalKind::RESTORE_RECONCILED, [
            'file_sha256'       => str_repeat('f', 64),
            'owners'            => 1,
            'erased'            => 1,
            'already_erased'    => 0,
            'anchored_sequence' => 3,
            'anchored_digest'   => $digest,
        ]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A custom field encrypter is a `[privacy] note:` and the run exits 0.
     *
     * @return void
     */
    public function testACustomEncrypterIsAPrivacyNote(): void
    {
        $this->app?->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame([
            self::SPILL_NOTE,
            '[privacy] note: The bound field encrypter `' . RecordingFieldEncrypter::class . '` keeps its keys where the package cannot see them, so'
                . ' `audit-log:erase` refuses, `holdingDataOf()` throws, and the key store is neither checked nor verified.',
        ], array_slice($output, -2));
    }

    /**
     * Lifecycle notes leave the exit code at 0.
     *
     * @return void
     */
    public function testNotesLeaveTheExitCodeAsItIs(): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        $hold = app(HoldKeeper::class)->place(
            '01932b4e-9000-7000-8000-0000000000a1',
            HoldScope::all(),
            new Authority(Reference::of('App\Models\User', '7'), 'case.review'),
            HoldBasis::LEGAL_CLAIM,
            new CarbonImmutable('2026-11-03 00:00:00', 'UTC'),
        );

        DB::table('audit_log_import_batches')->insert(self::batchRow('01932b4e-b000-7000-8000-000000000001', '2026-11-02 09:00:00.000000'));

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 09:00:00', 'UTC'));

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame([
            self::SPILL_NOTE,
            "[lifecycle] note: 1 hold is past its review date: `{$hold->id}`; review each, and release it once nothing obliges keeping it.",
            '[lifecycle] note: 1 import batch is running with nothing written for over an hour: `01932b4e-b000-7000-8000-000000000001`;'
                . ' close an interrupted one with `audit-log:import --close=<batch>`.',
        ], array_slice($output, -3));
    }

    /**
     * A retention shorter than its preservation is a `config` problem.
     *
     * @return void
     */
    public function testARetentionShorterThanItsPreservationIsAProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.retention.categories', ['security' => 30]);
        $config->set('audit-log.retention.preserve', ['security' => 60]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame(
            [
                '[config] `audit-log.retention.categories.security` is shorter than `audit-log.retention.preserve.security`;'
                    . ' a category must be kept at least as long as it is preserved.',
            ],
            self::problemsIn($output),
        );
        self::assertContains('[lifecycle] OK', $output);
    }

    /**
     * Every malformed lifecycle setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedLifecycleLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        foreach (self::BAD_LEAVES as $leaf => $bad) {

            if (!str_starts_with($leaf, 'lifecycle.') && !str_starts_with($leaf, 'retention.') && !str_starts_with($leaf, 'import.')) {
                continue;
            }

            $config->set("audit-log.{$leaf}", $bad);
        }

        $table = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';
        $map   = ' must be a map of categories to days, each from 0 to 36500, 0 meaning forever.';

        self::assertSame([
            '[config] `audit-log.lifecycle.journal_table`' . $table,
            '[config] `audit-log.lifecycle.holds_table`' . $table,
            '[config] `audit-log.lifecycle.lock_table`' . $table,
            '[config] `audit-log.import.batches_table`' . $table,
            '[config] `audit-log.retention.after_days` must be an integer from 0 to 36500.',
            '[config] `audit-log.retention.categories`' . $map,
            '[config] `audit-log.retention.preserve`' . $map,
            '[config] `audit-log.retention.batch` must be an integer from 100 to 10000.',
            '[config] `audit-log.retention.max_seconds` must be an integer from 60 to 86400.',
            '[config] `audit-log.retention.schedule` must be a cron expression, or null or empty to schedule nothing.',
            '[config] `audit-log.import.chunk` must be an integer from 100 to 5000.',
            '[config] `audit-log.import.max_skew_seconds` must be an integer from 0 to 86400.',
            '[config] `audit-log.import.max_line_bytes` must be an integer from 1024 to 16777216.',
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]` for lifecycle.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, int|string>|string, 2: string}>
     */
    public static function provideLifecycleValuesThatMustNotBePrinted(): iterable
    {
        yield from [
            'a journal table'             => ['audit-log.lifecycle.journal_table', self::SENTINEL, self::SENTINEL],
            'a lock table that is a list' => ['audit-log.lifecycle.lock_table', [self::SENTINEL], self::SENTINEL],
            'a batches table'             => ['audit-log.import.batches_table', self::SENTINEL, self::SENTINEL],
            'a retention'                 => ['audit-log.retention.after_days', self::SENTINEL, self::SENTINEL],
            'a category of no grammar'    => ['audit-log.retention.categories', [self::SENTINEL . '!' => 30], self::SENTINEL],
            'a category\'s retention'     => ['audit-log.retention.categories', ['security' => self::SENTINEL], self::SENTINEL],
            'a preservation'              => ['audit-log.retention.preserve', ['security' => self::SENTINEL], self::SENTINEL],
            'a schedule'                  => ['audit-log.retention.schedule', self::SENTINEL, self::SENTINEL],
            'a chunk'                     => ['audit-log.import.chunk', self::SENTINEL, self::SENTINEL],
            'a line limit'                => ['audit-log.import.max_line_bytes', self::SENTINEL, self::SENTINEL],
        ];
    }

    /**
     * A bad lifecycle setting fails the run and its value is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, int|string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideLifecycleValuesThatMustNotBePrinted')]
    public function testThePrintedOutputHoldsNoValueOfALifecycleSetting(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringContainsString("`{$setting}", implode("\n", $output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]` for owners' keys.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function providePrivacyValuesThatMustNotBePrinted(): iterable
    {
        yield from [
            'a wrapping ring that is a string' => ['audit-log.privacy.keys', self::SENTINEL, self::SENTINEL],
            'a wrapping secret too short'      => ['audit-log.privacy.keys', ['w1' => self::SENTINEL], self::SENTINEL],
            'a wrapping key id of no grammar'  => ['audit-log.privacy.keys', [self::SENTINEL . '!' => str_repeat('w', 32)], self::SENTINEL],
            'a current key in no ring'         => ['audit-log.privacy.current', self::SENTINEL, self::SENTINEL],
            'a subject keys table'             => ['audit-log.privacy.subject_keys_table', self::SENTINEL . '!', self::SENTINEL],
            'an owner erasures table'          => ['audit-log.privacy.owner_erasures_table', [self::SENTINEL], self::SENTINEL],
            'a key uses table'                 => ['audit-log.privacy.key_uses_table', self::SENTINEL . '-', self::SENTINEL],
            'a rewrap batch'                   => ['audit-log.privacy.rewrap_batch', self::SENTINEL, self::SENTINEL],
        ];
    }

    /**
     * A bad owners' key setting fails the run and its value is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('providePrivacyValuesThatMustNotBePrinted')]
    public function testThePrintedOutputHoldsNoValueOfAPrivacySetting(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringContainsString("`{$setting}", implode("\n", $output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * With an integrity ring, the wrapping keys check the application keys.
     *
     * @return void
     */
    public function testTheWrappingKeysDerivedFromTheApplicationKeysAreChecked(): void
    {
        $config = app(ConfigRepository::class);

        $config->set([...self::RING, 'app.key' => str_repeat('k', 32), 'app.previous_keys' => [self::SHORT_SECRET]]);

        self::assertSame([self::MALFORMED_WRAPPING_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set(['app.previous_keys' => [], 'app.key' => '']);

        self::assertSame([self::MISSING_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set('audit-log.redaction.key', str_repeat('r', 32));

        self::assertSame([self::MALFORMED_WRAPPING_APPLICATION_KEY], self::problemsIn($this->check()[1]));

        $config->set(self::WRAPPING_RING);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A delivery problem fails the run, listed after every other subject.
     *
     * @return void
     */
    public function testADeliveryProblemFailsTheRun(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', 'missing');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] The channel [missing] that `audit-log.failure.log_channel` names is not configured in `logging.channels`.',
            '[lifecycle] OK',
            '[privacy] OK',
            '[spill] The channel [missing] is not the documented file format, so replaying what it holds is unverified,'
                . ' and whole records in plaintext go to it and to everything it feeds.',
        ], $output);
    }

    /**
     * Outbox mode checks the outbox tables, so a missing one fails the run.
     *
     * @return void
     */
    public function testAnOutboxModeRunChecksTheOutboxTables(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.delivery.mode'         => 'outbox',
            'audit-log.delivery.outbox.table' => 'audit_absent_outbox',
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[delivery] The outbox table `audit_absent_outbox` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], self::problemsIn($output));
    }

    /**
     * An install the shipped migrations created passes in outbox mode too.
     *
     * @return void
     */
    public function testAGoodInstallPassesInOutboxMode(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A spill note on an undocumented channel leaves a clean run passing.
     *
     * @return void
     */
    public function testASpillNoteDoesNotFailTheRun(): void
    {
        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::SPILL_NOTE, end($output));
        self::assertSame([], self::problemsIn($output));
    }

    /**
     * The documented spill channel is said to be so, by the last line.
     *
     * @return void
     */
    public function testTheDocumentedChannelIsSaidToBeOk(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.audit_spill', DocumentedSpillChannel::config(sys_get_temp_dir() . '/audit-log-spill-' . getmypid() . '.log'));
        $config->set('audit-log.failure.log_channel', 'audit_spill');

        $passing = ['[config] OK', '[connections] OK', '[schema] OK', '[integrity] OK', '[delivery] OK', '[lifecycle] OK', '[privacy] OK', '[spill] OK'];

        self::assertSame([0, $passing], $this->check());
    }

    /**
     * A malformed delivery setting leaves only the delivery subject out.
     *
     * @return void
     */
    public function testAMalformedDeliverySettingSkipsTheSubject(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.delivery.mode', 'queue');

        $subjects = ['[connections] OK', '[schema] OK', '[integrity] OK', '[lifecycle] OK', '[privacy] OK'];

        self::assertSame([1, [self::MALFORMED_DELIVERY_MODE, ...$subjects, self::SPILL_NOTE]], $this->check());

        $config->set('audit-log.delivery.mode', 'sync');
        $config->set('audit-log.failure.log_channel', 42);

        self::assertSame([1, [self::MALFORMED_LOG_CHANNEL, ...$subjects]], $this->check());
    }

    /**
     * Every malformed delivery setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedDeliveryLeafIsReportedInOneRun(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.delivery.deliveries_table'       => 'audit-deliveries',
            'audit-log.delivery.outbox.connection'      => 42,
            'audit-log.delivery.outbox.table'           => 'audit-outbox',
            'audit-log.delivery.outbox.backoff_seconds' => 0,
            'audit-log.delivery.outbox.max_attempts'    => 0,
            'audit-log.delivery.outbox.lease_seconds'   => 29,
            'audit-log.delivery.mode'                   => 'queue',
            'audit-log.failure.log_channel'             => 42,
            'audit-log.failure.mode'                    => 'maybe',
            'audit-log.redaction.ip'                    => 'partial',
        ]);

        self::assertSame([
            self::MALFORMED_IP,
            self::MALFORMED_FAILURE_MODE,
            self::MALFORMED_LOG_CHANNEL,
            self::MALFORMED_DELIVERY_MODE,
            '[config] `audit-log.delivery.outbox.lease_seconds` must be an integer from 30 to 86400.',
            '[config] `audit-log.delivery.outbox.max_attempts` must be an integer from 1 to 1000.',
            '[config] `audit-log.delivery.outbox.backoff_seconds` must be an integer from 1 to 3600.',
            self::MALFORMED_OUTBOX_TABLE,
            self::MALFORMED_DELIVERIES_TABLE,
            '[config] `audit-log.delivery.outbox.connection` must be a connection name, or null or empty for the storage connection.',
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]` for delivery.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function provideDeliveryValuesThatMustNotBePrinted(): iterable
    {
        $long = str_repeat(self::SENTINEL, 8);

        yield from [
            'a failure mode'                 => ['audit-log.failure.mode', self::SENTINEL, self::SENTINEL],
            'a spill channel too long'       => ['audit-log.failure.log_channel', $long, self::SENTINEL],
            'a spill channel that is a list' => ['audit-log.failure.log_channel', [self::SENTINEL], self::SENTINEL],
            'a delivery mode'                => ['audit-log.delivery.mode', self::SENTINEL, self::SENTINEL],
            'an outbox connection'           => ['audit-log.delivery.outbox.connection', [self::SENTINEL], self::SENTINEL],
            'an outbox table'                => ['audit-log.delivery.outbox.table', self::SENTINEL, self::SENTINEL],
            'a lease'                        => ['audit-log.delivery.outbox.lease_seconds', self::SENTINEL, self::SENTINEL],
            'a number of attempts'           => ['audit-log.delivery.outbox.max_attempts', self::SENTINEL, self::SENTINEL],
            'a backoff'                      => ['audit-log.delivery.outbox.backoff_seconds', self::SENTINEL, self::SENTINEL],
            'a deliveries table'             => ['audit-log.delivery.deliveries_table', self::SENTINEL, self::SENTINEL],
        ];
    }

    /**
     * A bad delivery setting fails the run and its value is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideDeliveryValuesThatMustNotBePrinted')]
    public function testThePrintedOutputHoldsNoValueOfADeliverySetting(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringContainsString("`{$setting}`", implode("\n", $output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * An unconfigured excepted guard is one `[config]` problem, listed once.
     *
     * @return void
     */
    public function testAnUnconfiguredExceptGuardFailsTheConfigSubject(): void
    {
        app(ConfigRepository::class)->set('audit-log.capture.laravel.except_guards', ['missing', 'web', 'missing']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            sprintf(self::UNCONFIGURED_EXCEPT_GUARD, 'missing'),
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
            '[delivery] OK',
            '[lifecycle] OK',
            '[privacy] OK',
            self::SPILL_NOTE,
        ], $output);
    }

    /**
     * Configured excepted guards and the wildcard pass.
     *
     * @return void
     */
    public function testConfiguredExceptGuardsAndTheWildcardPass(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users']);
        $config->set('audit-log.capture.laravel.except_guards', ['api', 'web']);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.capture.laravel.except_guards', ['*']);
        $config->set('auth.guards.api', null);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A malformed excepted guard list is reported once, by its reader.
     *
     * @return void
     */
    public function testAMalformedExceptGuardListIsReportedOnce(): void
    {
        app(ConfigRepository::class)->set('audit-log.capture.laravel.except_guards', ['missing', '*']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] `audit-log.capture.laravel.except_guards` must be a list of guard names of 1 to 64 characters, or `[\'*\']`.',
        ], self::problemsIn($output));
    }

    /**
     * Every value at the edge of what a capture setting accepts passes.
     *
     * @return void
     */
    public function testTheCaptureSettingsAcceptEveryGoodValue(): void
    {
        $config = app(ConfigRepository::class);
        $guard  = str_repeat('g', 64);

        $config->set("auth.guards.{$guard}", ['driver' => 'session', 'provider' => 'users']);
        $config->set([
            'audit-log.capture.laravel.except_guards'  => [$guard],
            'audit-log.capture.laravel.identifier_key' => str_repeat('k', 64),
            'audit-log.capture.gate.enabled'           => true,
            'audit-log.capture.gate.only_abilities'    => [str_repeat('a', 191)],
            'audit-log.capture.gate.except_abilities'  => ['viewNova'],
            'audit-log.capture.gate.reason_codes'      => [str_repeat('r', 64)],
            'audit-log.capture.bulk.max_members'       => 1,
            'audit-log.capture.bulk.max_bytes'         => '65536',
            'audit-log.entries.artifacts_table'        => self::LONGEST_ARTIFACTS_TABLE,
        ]);

        $this->migrateArtifactsTable();

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.capture.bulk.max_members', '1000000');
        $config->set('audit-log.capture.bulk.max_bytes', 8388608);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * Every malformed capture setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedCaptureLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        foreach (array_reverse(self::BAD_LEAVES, true) as $leaf => $bad) {

            if (!str_starts_with($leaf, 'capture.') && $leaf !== 'entries.artifacts_table') {
                continue;
            }

            $config->set("audit-log.{$leaf}", $bad);
        }

        $capture = [
            '[config] `audit-log.capture.laravel.except_guards` must be a list of guard names of 1 to 64 characters, or `[\'*\']`.',
            '[config] `audit-log.capture.laravel.identifier_key` must be 1 to 64 letters, digits, underscores, dots or hyphens,'
                . ' starting with a letter, a digit or an underscore.',
            '[config] `audit-log.capture.gate.enabled` must be true or false.',
            '[config] `audit-log.capture.gate.only_abilities` must be null, or a non-empty list of abilities of 1 to 191 bytes.',
            '[config] `audit-log.capture.gate.except_abilities` must be a list of abilities of 1 to 191 bytes.',
            '[config] `audit-log.capture.gate.reason_codes` must be a list of machine-readable codes of 1 to 64 characters:'
                . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.',
            '[config] `audit-log.capture.bulk.max_members` must be an integer from 1 to 1000000.',
            '[config] `audit-log.capture.bulk.max_bytes` must be an integer from 65536 to 8388608.',
            '[config] `audit-log.entries.artifacts_table` must be a table name of 1 to 47 lower-case letters, digits and underscores'
                . ' that does not start with a digit.',
        ];

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([...$capture, '[connections] OK', '[schema] OK', '[integrity] OK', '[delivery] OK', '[lifecycle] OK', '[privacy] OK', self::SPILL_NOTE], $output);

        $config->set('audit-log.delivery.outbox.connection', 42);

        $delivery = '[config] `audit-log.delivery.outbox.connection` must be a connection name, or null or empty for the storage connection.';

        self::assertSame([$delivery, ...$capture], self::problemsIn($this->check()[1]));
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]` for capture.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function provideCaptureValuesThatMustNotBePrinted(): iterable
    {
        $long = str_repeat(self::SENTINEL, 8);

        yield from [
            'except guards that are a string'   => ['audit-log.capture.laravel.except_guards', self::SENTINEL, self::SENTINEL],
            'an except guard too long'          => ['audit-log.capture.laravel.except_guards', [$long], self::SENTINEL],
            'an except guard with a control'    => ['audit-log.capture.laravel.except_guards', [self::SENTINEL . ''], self::SENTINEL],
            'an except guard beside a wildcard' => ['audit-log.capture.laravel.except_guards', ['*', self::SENTINEL], self::SENTINEL],
            'an identifier key'                 => ['audit-log.capture.laravel.identifier_key', self::SENTINEL . ' x', self::SENTINEL],
            'a Gate flag'                       => ['audit-log.capture.gate.enabled', self::SENTINEL, self::SENTINEL],
            'only abilities that are a string'  => ['audit-log.capture.gate.only_abilities', self::SENTINEL, self::SENTINEL],
            'an only ability too long'          => ['audit-log.capture.gate.only_abilities', [$long . $long . $long . $long], self::SENTINEL],
            'an except ability with a control'  => ['audit-log.capture.gate.except_abilities', [self::SENTINEL . ''], self::SENTINEL],
            'a reason code'                     => ['audit-log.capture.gate.reason_codes', [self::SENTINEL . ' x'], self::SENTINEL],
            'a bulk bound on subjects'          => ['audit-log.capture.bulk.max_members', self::SENTINEL, self::SENTINEL],
            'a bulk bound on bytes'             => ['audit-log.capture.bulk.max_bytes', self::SENTINEL, self::SENTINEL],
            'an artifacts table'                => ['audit-log.entries.artifacts_table', self::SENTINEL, self::SENTINEL],
        ];
    }

    /**
     * A bad capture setting fails the run and its value is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideCaptureValuesThatMustNotBePrinted')]
    public function testThePrintedOutputHoldsNoValueOfACaptureSetting(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringContainsString("`{$setting}`", implode("\n", $output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * Every malformed read setting is listed by one run, in read order.
     *
     * @return void
     */
    public function testEveryMalformedReadLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        foreach (array_reverse(self::BAD_LEAVES, true) as $leaf => $bad) {

            if (!str_starts_with($leaf, 'read.') && !str_starts_with($leaf, 'export.')) {
                continue;
            }

            $config->set("audit-log.{$leaf}", $bad);
        }

        $read = [
            '[config] `audit-log.read.max_per_page` must be an integer from 1 to 500.',
            '[config] `audit-log.export.chunk` must be an integer from 100 to 10000.',
        ];

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([...$read, '[connections] OK', '[schema] OK', '[integrity] OK', '[delivery] OK', '[lifecycle] OK', '[privacy] OK', self::SPILL_NOTE], $output);

        $config->set('audit-log.capture.bulk.max_members', 0);

        $capture = '[config] `audit-log.capture.bulk.max_members` must be an integer from 1 to 1000000.';

        self::assertSame([$capture, ...$read], self::problemsIn($this->check()[1]));
    }

    /**
     * Every value at the edge of what a read setting accepts passes.
     *
     * @return void
     */
    public function testTheReadSettingsAcceptEveryGoodValue(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(['audit-log.read.max_per_page' => 1, 'audit-log.export.chunk' => '100']);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set(['audit-log.read.max_per_page' => '500', 'audit-log.export.chunk' => 10000]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]` for reads.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function provideReadValuesThatMustNotBePrinted(): iterable
    {
        yield from [
            'a page size that is a word'  => ['audit-log.read.max_per_page', self::SENTINEL, self::SENTINEL],
            'a page size that is a list'  => ['audit-log.read.max_per_page', [self::SENTINEL], self::SENTINEL],
            'a page size over its most'   => ['audit-log.read.max_per_page', '501', '501'],
            'a chunk that is a word'      => ['audit-log.export.chunk', self::SENTINEL, self::SENTINEL],
            'a chunk that is an exponent' => ['audit-log.export.chunk', '1e3', '1e3'],
            'a chunk under its least'     => ['audit-log.export.chunk', '99', '99'],
        ];
    }

    /**
     * A bad read setting fails the run and its value is never printed.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideReadValuesThatMustNotBePrinted')]
    public function testThePrintedOutputHoldsNoValueOfAReadSetting(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertCount(1, self::problemsIn($output));
        self::assertStringContainsString("`{$setting}`", implode("\n", $output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * Rows of `[the settings changed, the one problem]` for integrity settings.
     *
     * @return array<string, array{0: array<string, array<array-key, int|string>|int|string|null>, 1: string}>
     */
    private static function badIntegritySettings(): array
    {
        $table  = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';
        $cron   = ' must be a cron expression, or null or empty to schedule nothing.';
        $named  = static fn (string $leaf, string $rest): string => "[config] `audit-log.integrity.{$leaf}`{$rest}";
        $number = static fn (string $leaf, int $least, int $most): string => $named($leaf, sprintf(' must be an integer from %d to %d.', $least, $most));
        $path   = ' must be 1 to 191 characters of path segments of letters, digits, dots, underscores and hyphens, separated by single slashes,'
            . ' with no `.` or `..` segment.';
        $source = '[config] `audit-log.integrity.log_id` is empty, so `audit-log.source.id` is the log id, and it must be 1 to 64 letters, digits,'
            . ' dots, underscores or hyphens, starting with a letter or a digit.';

        return [
            'a log id with a slash'                  => [['audit-log.integrity.log_id' => 'app/eu'], self::MALFORMED_LOG_ID],
            'a log id starting with a dot'           => [['audit-log.integrity.log_id' => '.app'], self::MALFORMED_LOG_ID],
            'a log id of 65 characters'              => [['audit-log.integrity.log_id' => str_repeat('l', 65)], self::MALFORMED_LOG_ID],
            'a log id that is a number'              => [['audit-log.integrity.log_id' => 42], self::MALFORMED_LOG_ID],
            'a source id that is no log id'          => [['audit-log.source.id' => 'billing eu'], $source],
            'a checkpoints table with capitals'      => [['audit-log.integrity.checkpoints_table' => 'Seals'], $named('checkpoints_table', $table)],
            'a members table with a hyphen'          => [['audit-log.integrity.members_table' => 'seal-members'], $named('members_table', $table)],
            'a state table of 48 characters'         => [['audit-log.integrity.state_table' => str_repeat('s', 48)], $named('state_table', $table)],
            'a sealing schedule that is a word'      => [['audit-log.integrity.seal.schedule' => 'often'], $named('seal.schedule', $cron)],
            'a sweep schedule out of range'          => [['audit-log.integrity.seal.sweep_schedule' => '15 25 * * *'], $named('seal.sweep_schedule', $cron)],
            'a verification schedule that is a list' => [['audit-log.integrity.verify.schedule' => ['45 3 * * *']], $named('verify.schedule', $cron)],
            'a batch under its minimum'              => [['audit-log.integrity.seal.batch' => 99], $number('seal.batch', 100, 50000)],
            'a batch over its ceiling'               => [['audit-log.integrity.seal.batch' => 50001], $number('seal.batch', 100, 50000)],
            'no batches'                             => [['audit-log.integrity.seal.max_batches' => 0], $number('seal.max_batches', 1, 100000)],
            'a lookback over its ceiling'            => [['audit-log.integrity.seal.lookback_seconds' => 2592001], $number('seal.lookback_seconds', 0, 2592000)],
            'a negative settle'                      => [['audit-log.integrity.seal.settle_seconds' => -1], $number('seal.settle_seconds', 0, 3600)],
            'no seal attempts'                       => [['audit-log.integrity.seal.max_attempts' => 0], $number('seal.max_attempts', 1, 100)],
            'an overdue age under its minimum'       => [['audit-log.integrity.verify.max_unsealed_age_seconds' => 599], $number('verify.max_unsealed_age_seconds', 600, 31536000)],
            'an anchor driver that is unknown'       => [['audit-log.integrity.anchor.driver' => 's3'], $named('anchor.driver', ' must be `null` or `disk`.')],
            'an anchor driver in capitals'           => [['audit-log.integrity.anchor.driver' => 'DISK'], $named('anchor.driver', ' must be `null` or `disk`.')],
            'an anchor disk of 65 characters'        => [
                ['audit-log.integrity.anchor.disk' => str_repeat('d', 65)],
                $named('anchor.disk', ' must be a disk name of 1 to 64 characters, or null or empty for the default disk.'),
            ],
            'an anchor path that leaves its place'  => [['audit-log.integrity.anchor.path' => 'anchors/../../etc'], $named('anchor.path', $path)],
            'an anchor batch over its ceiling'      => [['audit-log.integrity.anchor.batch' => 10001], $number('anchor.batch', 1, 10000)],
            'an anchor disk that is not configured' => [['audit-log.integrity.anchor.driver' => 'disk', 'audit-log.integrity.anchor.disk' => 'anchors'], self::UNCONFIGURED_DISK],
        ];
    }

    /**
     * Run the command and return its exit code and its output lines.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function check(): array
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $code = $kernel->call('audit-log:check');

        return [$code, array_values(array_filter(array_map(trim(...), explode("\n", $kernel->output())), static fn (string $line): bool => $line !== ''))];
    }

    /**
     * The output lines other than a subject's `OK` and the spill note.
     *
     * @param  list<string>  $output
     * @return list<string>
     */
    private static function problemsIn(array $output): array
    {
        return array_values(array_filter($output, static fn (string $line): bool => preg_match('/\A\[[a-z]+\] OK\z/', $line) !== 1 && !str_starts_with($line, '[spill] ')));
    }

    /**
     * The leaf paths under the settings; an empty map or a list is a leaf.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $settings
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leavesOf(array $settings, string $prefix = ''): array
    {
        $leaves = [];

        foreach ($settings as $key => $value) {
            $leaves = is_array($value) && $value !== [] && !array_is_list($value)
                ? [...$leaves, ...self::leavesOf($value, "{$prefix}{$key}.")]
                : [...$leaves, "{$prefix}{$key}"];
        }

        return $leaves;
    }

    /**
     * Run the shipped entries and artifacts migrations.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrate(): void
    {
        foreach (self::MIGRATION_PATHS as $path) {

            $migration = include $path;

            if (!$migration instanceof Migration) {
                self::fail('An entries or artifacts migration file did not return a Migration instance.');
            }

            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Run the shipped artifacts migration.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateArtifactsTable(): void
    {
        $migration = include self::MIGRATION_PATHS[1];

        if (!$migration instanceof Migration) {
            self::fail('The artifacts migration file did not return a Migration instance.');
        }

        $migration->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Run the shipped integrity migrations.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateIntegrityTables(): void
    {
        foreach (self::INTEGRITY_MIGRATION_PATHS as $path) {

            $migration = include $path;

            if (!$migration instanceof Migration) {
                self::fail('An integrity migration file did not return a Migration instance.');
            }

            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Run the shipped lifecycle migrations.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateLifecycleTables(): void
    {
        foreach (self::LIFECYCLE_MIGRATION_PATHS as $path) {

            $migration = include $path;

            if (!$migration instanceof Migration) {
                self::fail('A lifecycle migration file did not return a Migration instance.');
            }

            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Run the shipped owners' key migrations.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateKeyTables(): void
    {
        foreach (self::KEY_MIGRATION_PATHS as $path) {

            $migration = include $path;

            if (!$migration instanceof Migration) {
                self::fail('An owners\' key migration file did not return a Migration instance.');
            }

            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * An import batch row, `running`, last written at the stored time given.
     *
     * @param  string  $id
     * @param  string  $updatedAt
     * @return array<string, bool|int|string|null>
     */
    private static function batchRow(string $id, string $updatedAt): array
    {
        return [
            'id'                  => $id,
            'source_id'           => 'legacy',
            'source_region'       => null,
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => null,
            'file_sha256'         => str_repeat('a', 64),
            'externally_verified' => false,
            'hold_id'             => null,
            'status'              => 'running',
            'lines_read'          => 0,
            'imported'            => 0,
            'duplicates'          => 0,
            'conflicts'           => 0,
            'rejected'            => 0,
            'conflict_ids'        => null,
            'started_at'          => $updatedAt,
            'updated_at'          => $updatedAt,
            'finished_at'         => null,
        ];
    }

    /**
     * A file that exists but is not a database, removed when the test ends.
     *
     * @return string
     */
    private function garbageFile(): string
    {
        $path = sys_get_temp_dir() . '/audit-log-garbage-' . getmypid() . '.sqlite';

        file_put_contents($path, str_repeat('not a database ', 512));

        $this->files[] = $path;

        return $path;
    }
}
