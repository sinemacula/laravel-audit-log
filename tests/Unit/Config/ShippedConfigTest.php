<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;

/**
 * Unit tests for the shipped `config/audit-log.php`: the env vars it reads, the
 * defaults it falls back to and the leaves it ships, so a renamed key or env
 * var, or an added or dropped leaf, fails here rather than shipping silently.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ShippedConfigTest extends TestCase
{
    /** @var string The shipped configuration file. */
    private const string CONFIG = __DIR__ . '/../../../config/audit-log.php';

    /** @var string Env var naming the storage connection. */
    private const string CONNECTION_ENV = 'AUDIT_LOG_STORAGE_CONNECTION';

    /** @var string Env var naming the maintenance connection. */
    private const string MAINTENANCE_ENV = 'AUDIT_LOG_STORAGE_MAINTENANCE_CONNECTION';

    /** @var string Env var naming the entries table. */
    private const string TABLE_ENV = 'AUDIT_LOG_ENTRIES_TABLE';

    /** @var string Env var naming the artifacts table. */
    private const string ARTIFACTS_TABLE_ENV = 'AUDIT_LOG_ENTRIES_ARTIFACTS_TABLE';

    /** @var string Env var naming the current integrity key. */
    private const string CURRENT_ENV = 'AUDIT_LOG_INTEGRITY_CURRENT';

    /** @var string Env var naming the log every seal names. */
    private const string LOG_ID_ENV = 'AUDIT_LOG_INTEGRITY_LOG_ID';

    /** @var string Env var naming the seals table. */
    private const string CHECKPOINTS_TABLE_ENV = 'AUDIT_LOG_INTEGRITY_CHECKPOINTS_TABLE';

    /** @var string Env var naming the checkpoint members table. */
    private const string MEMBERS_TABLE_ENV = 'AUDIT_LOG_INTEGRITY_MEMBERS_TABLE';

    /** @var string Env var naming the integrity state table. */
    private const string STATE_TABLE_ENV = 'AUDIT_LOG_INTEGRITY_STATE_TABLE';

    /** @var string Env var holding when sealing runs. */
    private const string SEAL_SCHEDULE_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_SCHEDULE';

    /** @var string Env var holding when the sweep runs. */
    private const string SWEEP_SCHEDULE_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_SWEEP_SCHEDULE';

    /** @var string Env var holding the most entries one seal holds. */
    private const string SEAL_BATCH_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_BATCH';

    /** @var string Env var holding the most seals one run writes. */
    private const string SEAL_MAX_BATCHES_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_MAX_BATCHES';

    /** @var string Env var holding how far back a recent pass starts. */
    private const string SEAL_LOOKBACK_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_LOOKBACK_SECONDS';

    /** @var string Env var holding how long an entry waits before it is sealed. */
    private const string SEAL_SETTLE_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_SETTLE_SECONDS';

    /** @var string Env var holding how many attempts a seal gets. */
    private const string SEAL_ATTEMPTS_ENV = 'AUDIT_LOG_INTEGRITY_SEAL_MAX_ATTEMPTS';

    /** @var string Env var holding when the strict verification runs. */
    private const string VERIFY_SCHEDULE_ENV = 'AUDIT_LOG_INTEGRITY_VERIFY_SCHEDULE';

    /** @var string Env var holding how old an unsealed entry may grow. */
    private const string VERIFY_MAX_AGE_ENV = 'AUDIT_LOG_INTEGRITY_VERIFY_MAX_UNSEALED_AGE_SECONDS';

    /** @var string Env var naming the anchor. */
    private const string ANCHOR_DRIVER_ENV = 'AUDIT_LOG_INTEGRITY_ANCHOR_DRIVER';

    /** @var string Env var naming the disk anchor's disk. */
    private const string ANCHOR_DISK_ENV = 'AUDIT_LOG_INTEGRITY_ANCHOR_DISK';

    /** @var string Env var naming the disk anchor's path. */
    private const string ANCHOR_PATH_ENV = 'AUDIT_LOG_INTEGRITY_ANCHOR_PATH';

    /** @var string Env var holding how many seals one run anchors. */
    private const string ANCHOR_BATCH_ENV = 'AUDIT_LOG_INTEGRITY_ANCHOR_BATCH';

    /** @var string Env var turning on trust in an inbound request id. */
    private const string TRUST_REQUEST_ID_ENV = 'AUDIT_LOG_CONTEXT_TRUST_REQUEST_ID';

    /** @var string Env var naming the request id's header. */
    private const string REQUEST_ID_HEADER_ENV = 'AUDIT_LOG_CONTEXT_REQUEST_ID_HEADER';

    /** @var string Env var turning on trust in an inbound `traceparent`. */
    private const string TRUST_TRACEPARENT_ENV = 'AUDIT_LOG_CONTEXT_TRUST_TRACEPARENT';

    /** @var string Env var refusing a code with no registered definition. */
    private const string REQUIRE_REGISTERED_ENV = 'AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED';

    /** @var string Env var naming the credential a failed sign-in is read for. */
    private const string IDENTIFIER_KEY_ENV = 'AUDIT_LOG_CAPTURE_LARAVEL_IDENTIFIER_KEY';

    /** @var string Env var turning on the capture of Gate denials. */
    private const string GATE_ENABLED_ENV = 'AUDIT_LOG_CAPTURE_GATE_ENABLED';

    /** @var string Env var holding the most subjects a manifest holds. */
    private const string BULK_MAX_MEMBERS_ENV = 'AUDIT_LOG_CAPTURE_BULK_MAX_MEMBERS';

    /** @var string Env var holding the most bytes a manifest encodes to. */
    private const string BULK_MAX_BYTES_ENV = 'AUDIT_LOG_CAPTURE_BULK_MAX_BYTES';

    /** @var string Env var naming the source's id. */
    private const string SOURCE_ID_ENV = 'AUDIT_LOG_SOURCE_ID';

    /** @var string Env var naming the source's region. */
    private const string SOURCE_REGION_ENV = 'AUDIT_LOG_SOURCE_REGION';

    /** @var string Env var holding the redaction key. */
    private const string REDACTION_KEY_ENV = 'AUDIT_LOG_REDACTION_KEY';

    /** @var string Env var naming how a sign-in identifier is stored. */
    private const string REDACTION_IDENTIFIERS_ENV = 'AUDIT_LOG_REDACTION_IDENTIFIERS';

    /** @var string Env var naming how an IP address is stored. */
    private const string REDACTION_IP_ENV = 'AUDIT_LOG_REDACTION_IP';

    /** @var string Env var holding the budget of the properties. */
    private const string REDACTION_MAX_BYTES_ENV = 'AUDIT_LOG_REDACTION_MAX_BYTES';

    /** @var string Env var holding the budget of the context. */
    private const string REDACTION_MAX_CONTEXT_BYTES_ENV = 'AUDIT_LOG_REDACTION_MAX_CONTEXT_BYTES';

    /** @var string Env var naming what a failed write does. */
    private const string FAILURE_MODE_ENV = 'AUDIT_LOG_FAILURE_MODE';

    /** @var string Env var naming the channel of the spill lines. */
    private const string FAILURE_LOG_CHANNEL_ENV = 'AUDIT_LOG_FAILURE_LOG_CHANNEL';

    /** @var string Env var naming how a record reaches its store. */
    private const string DELIVERY_MODE_ENV = 'AUDIT_LOG_DELIVERY_MODE';

    /** @var string Env var naming the outbox's connection. */
    private const string OUTBOX_CONNECTION_ENV = 'AUDIT_LOG_DELIVERY_OUTBOX_CONNECTION';

    /** @var string Env var naming the outbox's table. */
    private const string OUTBOX_TABLE_ENV = 'AUDIT_LOG_DELIVERY_OUTBOX_TABLE';

    /** @var string Env var holding how long a drain's claim lasts. */
    private const string OUTBOX_LEASE_ENV = 'AUDIT_LOG_DELIVERY_OUTBOX_LEASE_SECONDS';

    /** @var string Env var holding how many attempts a row gets. */
    private const string OUTBOX_ATTEMPTS_ENV = 'AUDIT_LOG_DELIVERY_OUTBOX_MAX_ATTEMPTS';

    /** @var string Env var holding how long the first retry waits. */
    private const string OUTBOX_BACKOFF_ENV = 'AUDIT_LOG_DELIVERY_OUTBOX_BACKOFF_SECONDS';

    /** @var string Env var naming the receipts table. */
    private const string DELIVERIES_TABLE_ENV = 'AUDIT_LOG_DELIVERY_DELIVERIES_TABLE';

    /** @var list<string> Every env var the shipped file reads. */
    private const array ENVS = [
        self::CONNECTION_ENV,
        self::MAINTENANCE_ENV,
        self::TABLE_ENV,
        self::ARTIFACTS_TABLE_ENV,
        self::CURRENT_ENV,
        self::LOG_ID_ENV,
        self::CHECKPOINTS_TABLE_ENV,
        self::MEMBERS_TABLE_ENV,
        self::STATE_TABLE_ENV,
        self::SEAL_SCHEDULE_ENV,
        self::SWEEP_SCHEDULE_ENV,
        self::SEAL_BATCH_ENV,
        self::SEAL_MAX_BATCHES_ENV,
        self::SEAL_LOOKBACK_ENV,
        self::SEAL_SETTLE_ENV,
        self::SEAL_ATTEMPTS_ENV,
        self::VERIFY_SCHEDULE_ENV,
        self::VERIFY_MAX_AGE_ENV,
        self::ANCHOR_DRIVER_ENV,
        self::ANCHOR_DISK_ENV,
        self::ANCHOR_PATH_ENV,
        self::ANCHOR_BATCH_ENV,
        self::TRUST_REQUEST_ID_ENV,
        self::REQUEST_ID_HEADER_ENV,
        self::TRUST_TRACEPARENT_ENV,
        self::REQUIRE_REGISTERED_ENV,
        self::IDENTIFIER_KEY_ENV,
        self::GATE_ENABLED_ENV,
        self::BULK_MAX_MEMBERS_ENV,
        self::BULK_MAX_BYTES_ENV,
        self::SOURCE_ID_ENV,
        self::SOURCE_REGION_ENV,
        self::REDACTION_KEY_ENV,
        self::REDACTION_IDENTIFIERS_ENV,
        self::REDACTION_IP_ENV,
        self::REDACTION_MAX_BYTES_ENV,
        self::REDACTION_MAX_CONTEXT_BYTES_ENV,
        self::FAILURE_MODE_ENV,
        self::FAILURE_LOG_CHANNEL_ENV,
        self::DELIVERY_MODE_ENV,
        self::OUTBOX_CONNECTION_ENV,
        self::OUTBOX_TABLE_ENV,
        self::OUTBOX_LEASE_ENV,
        self::OUTBOX_ATTEMPTS_ENV,
        self::OUTBOX_BACKOFF_ENV,
        self::DELIVERIES_TABLE_ENV,
    ];

    /**
     * Clear every env var after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::ENVS as $env) {
            putenv($env);
        }

        parent::tearDown();
    }

    /**
     * With nothing in the environment the tables live on the default
     * connection.
     *
     * @return void
     */
    public function testStorageConnectionDefaultsToTheDefaultConnection(): void
    {
        putenv(self::CONNECTION_ENV);

        self::assertNull($this->config()['storage']['connection']);
    }

    /**
     * The storage connection is read from its env var.
     *
     * @return void
     */
    public function testStorageConnectionIsReadFromTheEnvironment(): void
    {
        putenv(self::CONNECTION_ENV . '=audit');

        self::assertSame('audit', $this->config()['storage']['connection']);
    }

    /**
     * With nothing in the environment the maintenance connection is `null`,
     * which reads as the storage connection.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionDefaultsToTheStorageConnection(): void
    {
        putenv(self::MAINTENANCE_ENV);

        self::assertNull($this->config()['storage']['maintenance_connection']);
    }

    /**
     * The maintenance connection is read from its env var.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionIsReadFromTheEnvironment(): void
    {
        putenv(self::MAINTENANCE_ENV . '=audit_maintenance');

        self::assertSame('audit_maintenance', $this->config()['storage']['maintenance_connection']);
    }

    /**
     * With nothing in the environment the entries live in `audit_log_entries`.
     *
     * @return void
     */
    public function testTheEntriesTableDefaultsToAuditLogEntries(): void
    {
        putenv(self::TABLE_ENV);

        self::assertSame('audit_log_entries', $this->config()['entries']['table']);
    }

    /**
     * The entries table is read from its env var.
     *
     * @return void
     */
    public function testTheEntriesTableIsReadFromTheEnvironment(): void
    {
        putenv(self::TABLE_ENV . '=reporting_entries');

        self::assertSame('reporting_entries', $this->config()['entries']['table']);
    }

    /**
     * With nothing in the environment each bulk operation's manifest lives in
     * `audit_log_artifacts`.
     *
     * @return void
     */
    public function testTheArtifactsTableDefaultsToAuditLogArtifacts(): void
    {
        putenv(self::ARTIFACTS_TABLE_ENV);

        self::assertSame('audit_log_artifacts', $this->config()['entries']['artifacts_table']);
    }

    /**
     * The artifacts table is read from its env var, whatever the entries table
     * is.
     *
     * @return void
     */
    public function testTheArtifactsTableIsReadFromTheEnvironment(): void
    {
        putenv(self::ARTIFACTS_TABLE_ENV . '=reporting_artifacts');

        self::assertSame('reporting_artifacts', $this->config()['entries']['artifacts_table']);
        self::assertSame('audit_log_entries', $this->config()['entries']['table']);
    }

    /**
     * With nothing in the environment no key ring is configured, so the key is
     * derived from `app.key`.
     *
     * @return void
     */
    public function testTheIntegrityRingIsEmptyByDefault(): void
    {
        putenv(self::CURRENT_ENV);

        self::assertSame([], $this->config()['integrity']['keys']);
        self::assertNull($this->config()['integrity']['current']);
    }

    /**
     * The current integrity key is read from its env var.
     *
     * @return void
     */
    public function testTheCurrentIntegrityKeyIsReadFromTheEnvironment(): void
    {
        putenv(self::CURRENT_ENV . '=k2026');

        self::assertSame('k2026', $this->config()['integrity']['current']);
    }

    /**
     * With nothing in the environment the integrity tables have their default
     * names.
     *
     * @return void
     */
    public function testTheIntegrityTablesHaveTheirDefaults(): void
    {
        $integrity = $this->config()['integrity'];

        self::assertSame('audit_log_checkpoints', $integrity['checkpoints_table']);
        self::assertSame('audit_log_checkpoint_members', $integrity['members_table']);
        self::assertSame('audit_log_integrity_state', $integrity['state_table']);
    }

    /**
     * Each integrity table is read from its own env var.
     *
     * @return void
     */
    public function testTheIntegrityTablesAreReadFromTheEnvironment(): void
    {
        putenv(self::CHECKPOINTS_TABLE_ENV . '=audit_seals');
        putenv(self::MEMBERS_TABLE_ENV . '=audit_seal_members');
        putenv(self::STATE_TABLE_ENV . '=audit_seal_state');

        $integrity = $this->config()['integrity'];

        self::assertSame('audit_seals', $integrity['checkpoints_table']);
        self::assertSame('audit_seal_members', $integrity['members_table']);
        self::assertSame('audit_seal_state', $integrity['state_table']);
    }

    /**
     * With nothing in the environment no log id is set, so the source id is the
     * log id.
     *
     * @return void
     */
    public function testTheLogIdDefaultsToNone(): void
    {
        putenv(self::LOG_ID_ENV);

        self::assertNull($this->config()['integrity']['log_id']);
    }

    /**
     * The log id is read from its env var.
     *
     * @return void
     */
    public function testTheLogIdIsReadFromTheEnvironment(): void
    {
        putenv(self::LOG_ID_ENV . '=app-eu-1');

        self::assertSame('app-eu-1', $this->config()['integrity']['log_id']);
    }

    /**
     * With nothing in the environment sealing runs every five minutes, the
     * sweep daily, and the numbers have their defaults, as integers.
     *
     * @return void
     */
    public function testTheSealLeavesHaveTheirDefaults(): void
    {
        self::assertSame([
            'schedule'         => '*/5 * * * *',
            'sweep_schedule'   => '15 3 * * *',
            'batch'            => 5000,
            'max_batches'      => 100,
            'lookback_seconds' => 3600,
            'settle_seconds'   => 0,
            'max_attempts'     => 5,
        ], $this->config()['integrity']['seal']);
    }

    /**
     * Each sealing setting is read from its own env var, raw, so a malformed
     * number fails closed when it is read rather than casting to `0`.
     *
     * @return void
     */
    public function testTheSealLeavesAreReadFromTheEnvironment(): void
    {
        putenv(self::SEAL_SCHEDULE_ENV . '=*/10 * * * *');
        putenv(self::SWEEP_SCHEDULE_ENV . '=0 4 * * *');
        putenv(self::SEAL_BATCH_ENV . '=1000');
        putenv(self::SEAL_MAX_BATCHES_ENV . '=20');
        putenv(self::SEAL_LOOKBACK_ENV . '=7200');
        putenv(self::SEAL_SETTLE_ENV . '=30');
        putenv(self::SEAL_ATTEMPTS_ENV . '=3');

        self::assertSame([
            'schedule'         => '*/10 * * * *',
            'sweep_schedule'   => '0 4 * * *',
            'batch'            => '1000',
            'max_batches'      => '20',
            'lookback_seconds' => '7200',
            'settle_seconds'   => '30',
            'max_attempts'     => '3',
        ], $this->config()['integrity']['seal']);
    }

    /**
     * With nothing in the environment a strict verification runs daily, and an
     * unsealed entry is overdue after 25 hours, longer than the day a late
     * entry can wait for the sweep.
     *
     * @return void
     */
    public function testTheVerifyLeavesHaveTheirDefaults(): void
    {
        self::assertSame([
            'schedule'                 => '45 3 * * *',
            'max_unsealed_age_seconds' => 90000,
        ], $this->config()['integrity']['verify']);
    }

    /**
     * Each verification setting is read from its own env var, raw.
     *
     * @return void
     */
    public function testTheVerifyLeavesAreReadFromTheEnvironment(): void
    {
        putenv(self::VERIFY_SCHEDULE_ENV . '=30 2 * * 0');
        putenv(self::VERIFY_MAX_AGE_ENV . '=172800');

        self::assertSame([
            'schedule'                 => '30 2 * * 0',
            'max_unsealed_age_seconds' => '172800',
        ], $this->config()['integrity']['verify']);
    }

    /**
     * With nothing in the environment no anchor is configured, and a disk
     * anchor would write under `audit-log-anchors` on the default disk.
     *
     * @return void
     */
    public function testTheAnchorLeavesHaveTheirDefaults(): void
    {
        self::assertSame([
            'driver' => 'null',
            'disk'   => null,
            'path'   => 'audit-log-anchors',
            'batch'  => 100,
        ], $this->config()['integrity']['anchor']);
    }

    /**
     * Each anchor setting is read from its own env var, raw.
     *
     * @return void
     */
    public function testTheAnchorLeavesAreReadFromTheEnvironment(): void
    {
        putenv(self::ANCHOR_DRIVER_ENV . '=disk');
        putenv(self::ANCHOR_DISK_ENV . '=anchors');
        putenv(self::ANCHOR_PATH_ENV . '=seals/eu');
        putenv(self::ANCHOR_BATCH_ENV . '=500');

        self::assertSame([
            'driver' => 'disk',
            'disk'   => 'anchors',
            'path'   => 'seals/eu',
            'batch'  => '500',
        ], $this->config()['integrity']['anchor']);
    }

    /**
     * The shipped default driver, and `null` in the environment, which `env()`
     * reads as `null`, are each no anchor.
     *
     * @return void
     */
    public function testTheDefaultDriverAndANullEnvAreNoAnchor(): void
    {
        self::assertSame(AnchorDriver::NONE, $this->anchorSettings()->driver());

        putenv(self::ANCHOR_DRIVER_ENV . '=null');

        self::assertNull($this->config()['integrity']['anchor']['driver']);
        self::assertSame(AnchorDriver::NONE, $this->anchorSettings()->driver());
    }

    /**
     * An empty env line for a schedule turns its run off: the setting reads as
     * no schedule, rather than as a malformed expression.
     *
     * @return void
     */
    public function testAnEmptyScheduleEnvDisablesTheRun(): void
    {
        putenv(self::SEAL_SCHEDULE_ENV . '=');
        putenv(self::SWEEP_SCHEDULE_ENV . '=');
        putenv(self::VERIFY_SCHEDULE_ENV . '=');

        $seals = new SealSettings(new Repository(['audit-log' => $this->config()]));

        self::assertSame('', $this->config()['integrity']['seal']['schedule']);
        self::assertNull($seals->sealSchedule());
        self::assertNull($seals->sweepSchedule());
        self::assertNull($seals->verifySchedule());
    }

    /**
     * The shipped defaults pass the sealing and anchor settings, so a fresh
     * install schedules every run and needs no anchor.
     *
     * @return void
     */
    public function testTheShippedIntegrityDefaultsAreValid(): void
    {
        $config = new Repository(['audit-log' => $this->config(), 'filesystems' => ['default' => 'local']]);
        $seals  = new SealSettings($config);

        $config->set('audit-log.source.id', 'app-eu-1');

        $seals->validate();
        $this->anchorSettings()->validate();

        self::assertSame('*/5 * * * *', $seals->sealSchedule());
        self::assertSame('15 3 * * *', $seals->sweepSchedule());
        self::assertSame('45 3 * * *', $seals->verifySchedule());
        self::assertSame('app-eu-1', $seals->logId());
    }

    /**
     * With nothing configured the actor is read from the default guard.
     *
     * @return void
     */
    public function testActorGuardsDefaultToNone(): void
    {
        self::assertNull($this->config()['actor']['guards']);
    }

    /**
     * With nothing in the environment an inbound request id is not believed.
     *
     * @return void
     */
    public function testTrustRequestIdDefaultsToOff(): void
    {
        putenv(self::TRUST_REQUEST_ID_ENV);

        self::assertFalse($this->config()['context']['trust_request_id']);
    }

    /**
     * Trust in an inbound request id is read from its env var, raw, for the
     * settings class to validate.
     *
     * @return void
     */
    public function testTrustRequestIdIsReadFromTheEnvironment(): void
    {
        putenv(self::TRUST_REQUEST_ID_ENV . '=true');

        self::assertTrue($this->config()['context']['trust_request_id']);

        putenv(self::TRUST_REQUEST_ID_ENV . '=yes');

        self::assertSame('yes', $this->config()['context']['trust_request_id']);
    }

    /**
     * With nothing in the environment the request id's header is
     * `X-Request-Id`.
     *
     * @return void
     */
    public function testTheRequestIdHeaderDefaultsToXRequestId(): void
    {
        putenv(self::REQUEST_ID_HEADER_ENV);

        self::assertSame('X-Request-Id', $this->config()['context']['request_id_header']);
    }

    /**
     * The request id's header is read from its env var.
     *
     * @return void
     */
    public function testTheRequestIdHeaderIsReadFromTheEnvironment(): void
    {
        putenv(self::REQUEST_ID_HEADER_ENV . '=X-Correlation-Id');

        self::assertSame('X-Correlation-Id', $this->config()['context']['request_id_header']);
    }

    /**
     * With nothing in the environment an inbound `traceparent` is not believed.
     *
     * @return void
     */
    public function testTrustTraceparentDefaultsToOff(): void
    {
        putenv(self::TRUST_TRACEPARENT_ENV);

        self::assertFalse($this->config()['context']['trust_traceparent']);
    }

    /**
     * Trust in an inbound `traceparent` is read from its env var.
     *
     * @return void
     */
    public function testTrustTraceparentIsReadFromTheEnvironment(): void
    {
        putenv(self::TRUST_TRACEPARENT_ENV . '=true');

        self::assertTrue($this->config()['context']['trust_traceparent']);
    }

    /**
     * With nothing in the environment a code needs no registered definition.
     *
     * @return void
     */
    public function testRequireRegisteredDefaultsToOff(): void
    {
        putenv(self::REQUIRE_REGISTERED_ENV);

        self::assertFalse($this->config()['definitions']['require_registered']);
    }

    /**
     * Requiring registration is read from its env var.
     *
     * @return void
     */
    public function testRequireRegisteredIsReadFromTheEnvironment(): void
    {
        putenv(self::REQUIRE_REGISTERED_ENV . '=true');

        self::assertTrue($this->config()['definitions']['require_registered']);
    }

    /**
     * With nothing in the environment no guard is excepted, `email` is the
     * credential read, Gate capture is off and selects every ability with no
     * reason code kept, and a manifest holds 100000 subjects and 4194304 bytes,
     * as integers; and the shipped capture settings pass.
     *
     * @return void
     */
    public function testTheCaptureLeavesHaveTheirDefaults(): void
    {
        foreach ([self::IDENTIFIER_KEY_ENV, self::GATE_ENABLED_ENV, self::BULK_MAX_MEMBERS_ENV, self::BULK_MAX_BYTES_ENV] as $env) {
            putenv($env);
        }

        self::assertSame([
            'laravel' => [
                'except_guards'  => [],
                'identifier_key' => 'email',
            ],
            'gate' => [
                'enabled'          => false,
                'only_abilities'   => null,
                'except_abilities' => [],
                'reason_codes'     => [],
            ],
            'bulk' => [
                'max_members' => 100000,
                'max_bytes'   => 4194304,
            ],
        ], $this->config()['capture']);

        (new CaptureSettings(new Repository(['audit-log' => $this->config()])))->validate();
    }

    /**
     * Each capture setting with an env var is read from it, raw, so a malformed
     * number fails closed when it is read rather than casting to `0`, and the
     * flag is the boolean `env()` makes of `true`.
     *
     * @return void
     */
    public function testTheCaptureLeavesAreReadFromTheEnvironment(): void
    {
        putenv(self::IDENTIFIER_KEY_ENV . '=username');
        putenv(self::GATE_ENABLED_ENV . '=true');
        putenv(self::BULK_MAX_MEMBERS_ENV . '=5000');
        putenv(self::BULK_MAX_BYTES_ENV . '=65536');

        $capture = $this->config()['capture'];

        self::assertSame('username', $capture['laravel']['identifier_key']);
        self::assertTrue($capture['gate']['enabled']);
        self::assertSame('5000', $capture['bulk']['max_members']);
        self::assertSame('65536', $capture['bulk']['max_bytes']);

        $settings = new CaptureSettings(new Repository(['audit-log' => $this->config()]));

        self::assertSame('username', $settings->identifierKey());
        self::assertTrue($settings->isGateEnabled());
        self::assertSame(5000, $settings->bulkMaxMembers());
        self::assertSame(65536, $settings->bulkMaxBytes());

        putenv(self::GATE_ENABLED_ENV . '=yes');

        self::assertSame('yes', $this->config()['capture']['gate']['enabled']);
    }

    /**
     * With nothing in the environment the source has no id of its own, so it
     * takes a slug of the application's name.
     *
     * @return void
     */
    public function testTheSourceIdDefaultsToNone(): void
    {
        putenv(self::SOURCE_ID_ENV);

        self::assertNull($this->config()['source']['id']);
    }

    /**
     * The source's id is read from its env var.
     *
     * @return void
     */
    public function testTheSourceIdIsReadFromTheEnvironment(): void
    {
        putenv(self::SOURCE_ID_ENV . '=billing-eu');

        self::assertSame('billing-eu', $this->config()['source']['id']);
    }

    /**
     * With nothing in the environment the source has no region.
     *
     * @return void
     */
    public function testTheSourceRegionDefaultsToNone(): void
    {
        putenv(self::SOURCE_REGION_ENV);

        self::assertNull($this->config()['source']['region']);
    }

    /**
     * The source's region is read from its env var.
     *
     * @return void
     */
    public function testTheSourceRegionIsReadFromTheEnvironment(): void
    {
        putenv(self::SOURCE_REGION_ENV . '=eu-west-1');

        self::assertSame('eu-west-1', $this->config()['source']['region']);
    }

    /**
     * The shipped file has exactly these leaves, in this order, so an added,
     * renamed or dropped leaf fails here.
     *
     * @return void
     */
    public function testTheShippedLeavesArePinned(): void
    {
        self::assertSame([
            'storage.connection',
            'storage.maintenance_connection',
            'entries.table',
            'entries.artifacts_table',
            'integrity.keys',
            'integrity.current',
            'integrity.log_id',
            'integrity.checkpoints_table',
            'integrity.members_table',
            'integrity.state_table',
            'integrity.seal.schedule',
            'integrity.seal.sweep_schedule',
            'integrity.seal.batch',
            'integrity.seal.max_batches',
            'integrity.seal.lookback_seconds',
            'integrity.seal.settle_seconds',
            'integrity.seal.max_attempts',
            'integrity.verify.schedule',
            'integrity.verify.max_unsealed_age_seconds',
            'integrity.anchor.driver',
            'integrity.anchor.disk',
            'integrity.anchor.path',
            'integrity.anchor.batch',
            'actor.guards',
            'context.trust_request_id',
            'context.request_id_header',
            'context.trust_traceparent',
            'definitions.require_registered',
            'capture.laravel.except_guards',
            'capture.laravel.identifier_key',
            'capture.gate.enabled',
            'capture.gate.only_abilities',
            'capture.gate.except_abilities',
            'capture.gate.reason_codes',
            'capture.bulk.max_members',
            'capture.bulk.max_bytes',
            'source.id',
            'source.region',
            'redaction.keys',
            'redaction.key',
            'redaction.identifiers',
            'redaction.ip',
            'redaction.max_bytes',
            'redaction.max_context_bytes',
            'failure.mode',
            'failure.log_channel',
            'delivery.mode',
            'delivery.outbox.connection',
            'delivery.outbox.table',
            'delivery.outbox.lease_seconds',
            'delivery.outbox.max_attempts',
            'delivery.outbox.backoff_seconds',
            'delivery.deliveries_table',
        ], self::leavesOf($this->config()));
    }

    /**
     * With nothing in the environment no key name is added to the built-ins.
     *
     * @return void
     */
    public function testRedactionKeysDefaultToNone(): void
    {
        self::assertSame([], $this->config()['redaction']['keys']);
    }

    /**
     * With nothing in the environment there is no redaction key, which reads as
     * deriving it from `app.key`.
     *
     * @return void
     */
    public function testTheRedactionKeyDefaultsToNone(): void
    {
        putenv(self::REDACTION_KEY_ENV);

        self::assertNull($this->config()['redaction']['key']);
    }

    /**
     * The redaction key is read from its env var, as it is given.
     *
     * @return void
     */
    public function testTheRedactionKeyIsReadFromTheEnvironment(): void
    {
        putenv(self::REDACTION_KEY_ENV . '=base64:c2VjcmV0');

        self::assertSame('base64:c2VjcmV0', $this->config()['redaction']['key']);
    }

    /**
     * With nothing in the environment a sign-in identifier is hashed.
     *
     * @return void
     */
    public function testIdentifiersDefaultToHash(): void
    {
        putenv(self::REDACTION_IDENTIFIERS_ENV);

        self::assertSame('hash', $this->config()['redaction']['identifiers']);
    }

    /**
     * How a sign-in identifier is stored is read from its env var.
     *
     * @return void
     */
    public function testIdentifiersAreReadFromTheEnvironment(): void
    {
        putenv(self::REDACTION_IDENTIFIERS_ENV . '=drop');

        self::assertSame('drop', $this->config()['redaction']['identifiers']);
    }

    /**
     * With nothing in the environment an IP address is stored in full.
     *
     * @return void
     */
    public function testTheIpDefaultsToFull(): void
    {
        putenv(self::REDACTION_IP_ENV);

        self::assertSame('full', $this->config()['redaction']['ip']);
    }

    /**
     * How an IP address is stored is read from its env var.
     *
     * @return void
     */
    public function testTheIpModeIsReadFromTheEnvironment(): void
    {
        putenv(self::REDACTION_IP_ENV . '=truncate');

        self::assertSame('truncate', $this->config()['redaction']['ip']);
    }

    /**
     * With nothing in the environment the properties may hold 16384 bytes and
     * the context 4096, as integers.
     *
     * @return void
     */
    public function testTheByteBudgetsHaveTheirDefaults(): void
    {
        putenv(self::REDACTION_MAX_BYTES_ENV);
        putenv(self::REDACTION_MAX_CONTEXT_BYTES_ENV);

        $redaction = $this->config()['redaction'];

        self::assertSame(16384, $redaction['max_bytes']);
        self::assertSame(4096, $redaction['max_context_bytes']);
    }

    /**
     * Each byte budget is read from its own env var, raw, so a malformed one
     * fails closed when it is read rather than casting to `0`.
     *
     * @return void
     */
    public function testTheByteBudgetsAreReadFromTheEnvironment(): void
    {
        putenv(self::REDACTION_MAX_BYTES_ENV . '=9000');
        putenv(self::REDACTION_MAX_CONTEXT_BYTES_ENV . '=2000');

        $redaction = $this->config()['redaction'];

        self::assertSame('9000', $redaction['max_bytes']);
        self::assertSame('2000', $redaction['max_context_bytes']);
    }

    /**
     * With nothing in the environment a failed write is reported.
     *
     * @return void
     */
    public function testTheFailureModeDefaultsToReport(): void
    {
        putenv(self::FAILURE_MODE_ENV);

        self::assertSame('report', $this->config()['failure']['mode']);
    }

    /**
     * What a failed write does is read from its env var.
     *
     * @return void
     */
    public function testTheFailureModeIsReadFromTheEnvironment(): void
    {
        putenv(self::FAILURE_MODE_ENV . '=throw');

        self::assertSame('throw', $this->config()['failure']['mode']);
    }

    /**
     * With nothing in the environment no channel is named, so a spill line goes
     * to the default channel.
     *
     * @return void
     */
    public function testTheSpillChannelDefaultsToNone(): void
    {
        putenv(self::FAILURE_LOG_CHANNEL_ENV);

        self::assertNull($this->config()['failure']['log_channel']);
    }

    /**
     * The channel of the spill lines is read from its env var.
     *
     * @return void
     */
    public function testTheSpillChannelIsReadFromTheEnvironment(): void
    {
        putenv(self::FAILURE_LOG_CHANNEL_ENV . '=audit-spill');

        self::assertSame('audit-spill', $this->config()['failure']['log_channel']);
    }

    /**
     * With nothing in the environment a record goes straight to its store.
     *
     * @return void
     */
    public function testTheDeliveryModeDefaultsToSync(): void
    {
        putenv(self::DELIVERY_MODE_ENV);

        self::assertSame('sync', $this->config()['delivery']['mode']);
    }

    /**
     * How a record reaches its store is read from its env var.
     *
     * @return void
     */
    public function testTheDeliveryModeIsReadFromTheEnvironment(): void
    {
        putenv(self::DELIVERY_MODE_ENV . '=outbox');

        self::assertSame('outbox', $this->config()['delivery']['mode']);
    }

    /**
     * With nothing in the environment the outbox has its defaults, on the
     * storage connection.
     *
     * @return void
     */
    public function testTheOutboxHasItsDefaults(): void
    {
        self::assertSame([
            'connection'      => null,
            'table'           => 'audit_log_outbox',
            'lease_seconds'   => 300,
            'max_attempts'    => 10,
            'backoff_seconds' => 60,
        ], $this->config()['delivery']['outbox']);
    }

    /**
     * Each outbox setting is read from its own env var, raw, so a malformed
     * number fails closed when it is read rather than casting to `0`.
     *
     * @return void
     */
    public function testTheOutboxIsReadFromTheEnvironment(): void
    {
        putenv(self::OUTBOX_CONNECTION_ENV . '=business');
        putenv(self::OUTBOX_TABLE_ENV . '=audit_waiting');
        putenv(self::OUTBOX_LEASE_ENV . '=600');
        putenv(self::OUTBOX_ATTEMPTS_ENV . '=5');
        putenv(self::OUTBOX_BACKOFF_ENV . '=30');

        self::assertSame([
            'connection'      => 'business',
            'table'           => 'audit_waiting',
            'lease_seconds'   => '600',
            'max_attempts'    => '5',
            'backoff_seconds' => '30',
        ], $this->config()['delivery']['outbox']);
    }

    /**
     * With nothing in the environment the receipts have their own table.
     *
     * @return void
     */
    public function testTheDeliveriesTableHasItsDefault(): void
    {
        putenv(self::DELIVERIES_TABLE_ENV);

        self::assertSame('audit_log_deliveries', $this->config()['delivery']['deliveries_table']);
    }

    /**
     * The receipts table is read from its env var.
     *
     * @return void
     */
    public function testTheDeliveriesTableIsReadFromTheEnvironment(): void
    {
        putenv(self::DELIVERIES_TABLE_ENV . '=audit_receipts');

        self::assertSame('audit_receipts', $this->config()['delivery']['deliveries_table']);
    }

    /**
     * The anchor settings over the shipped configuration as the environment
     * gives it now, with `local` as the default disk.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings
     */
    private function anchorSettings(): AnchorSettings
    {
        return new AnchorSettings(new Repository(['audit-log' => $this->config(), 'filesystems' => ['default' => 'local']]));
    }

    /**
     * The dotted leaves of a settings map, a list or an empty map being one
     * leaf.
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
     * Load the shipped configuration file afresh.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{storage: array{connection: ?string, maintenance_connection: ?string}, entries: array{table: string, artifacts_table: string}, integrity: array{keys: array<string, string>, current: ?string, log_id: ?string, checkpoints_table: string, members_table: string, state_table: string, seal: array{schedule: ?string, sweep_schedule: ?string, batch: int|string, max_batches: int|string, lookback_seconds: int|string, settle_seconds: int|string, max_attempts: int|string}, verify: array{schedule: ?string, max_unsealed_age_seconds: int|string}, anchor: array{driver: ?string, disk: ?string, path: string, batch: int|string}}, actor: array{guards: ?list<string>}, context: array{trust_request_id: bool|string, request_id_header: string, trust_traceparent: bool|string}, definitions: array{require_registered: bool|string}, capture: array{laravel: array{except_guards: list<string>, identifier_key: string}, gate: array{enabled: bool|string, only_abilities: ?list<string>, except_abilities: list<string>, reason_codes: list<string>}, bulk: array{max_members: int|string, max_bytes: int|string}}, source: array{id: ?string, region: ?string}, redaction: array{keys: list<string>, key: ?string, identifiers: string, ip: string, max_bytes: int|string, max_context_bytes: int|string}, failure: array{mode: string, log_channel: ?string}, delivery: array{mode: string, outbox: array{connection: ?string, table: string, lease_seconds: int|string, max_attempts: int|string, backoff_seconds: int|string}, deliveries_table: string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function config(): array
    {
        /** @var array{storage: array{connection: ?string, maintenance_connection: ?string}, entries: array{table: string, artifacts_table: string}, integrity: array{keys: array<string, string>, current: ?string, log_id: ?string, checkpoints_table: string, members_table: string, state_table: string, seal: array{schedule: ?string, sweep_schedule: ?string, batch: int|string, max_batches: int|string, lookback_seconds: int|string, settle_seconds: int|string, max_attempts: int|string}, verify: array{schedule: ?string, max_unsealed_age_seconds: int|string}, anchor: array{driver: ?string, disk: ?string, path: string, batch: int|string}}, actor: array{guards: ?list<string>}, context: array{trust_request_id: bool|string, request_id_header: string, trust_traceparent: bool|string}, definitions: array{require_registered: bool|string}, capture: array{laravel: array{except_guards: list<string>, identifier_key: string}, gate: array{enabled: bool|string, only_abilities: ?list<string>, except_abilities: list<string>, reason_codes: list<string>}, bulk: array{max_members: int|string, max_bytes: int|string}}, source: array{id: ?string, region: ?string}, redaction: array{keys: list<string>, key: ?string, identifiers: string, ip: string, max_bytes: int|string, max_context_bytes: int|string}, failure: array{mode: string, log_channel: ?string}, delivery: array{mode: string, outbox: array{connection: ?string, table: string, lease_seconds: int|string, max_attempts: int|string, backoff_seconds: int|string}, deliveries_table: string}} $config */
        $config = require self::CONFIG;

        return $config;
    }
}
