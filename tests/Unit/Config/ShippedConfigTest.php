<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

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

    /** @var string Env var naming the current integrity key. */
    private const string CURRENT_ENV = 'AUDIT_LOG_INTEGRITY_CURRENT';

    /** @var string Env var turning on trust in an inbound request id. */
    private const string TRUST_REQUEST_ID_ENV = 'AUDIT_LOG_CONTEXT_TRUST_REQUEST_ID';

    /** @var string Env var naming the request id's header. */
    private const string REQUEST_ID_HEADER_ENV = 'AUDIT_LOG_CONTEXT_REQUEST_ID_HEADER';

    /** @var string Env var turning on trust in an inbound `traceparent`. */
    private const string TRUST_TRACEPARENT_ENV = 'AUDIT_LOG_CONTEXT_TRUST_TRACEPARENT';

    /** @var string Env var refusing a code with no registered definition. */
    private const string REQUIRE_REGISTERED_ENV = 'AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED';

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
        self::CURRENT_ENV,
        self::TRUST_REQUEST_ID_ENV,
        self::REQUEST_ID_HEADER_ENV,
        self::TRUST_TRACEPARENT_ENV,
        self::REQUIRE_REGISTERED_ENV,
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
            'integrity.keys',
            'integrity.current',
            'actor.guards',
            'context.trust_request_id',
            'context.request_id_header',
            'context.trust_traceparent',
            'definitions.require_registered',
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
     * @return array{storage: array{connection: ?string, maintenance_connection: ?string}, entries: array{table: string}, integrity: array{keys: array<string, string>, current: ?string}, actor: array{guards: ?list<string>}, context: array{trust_request_id: bool|string, request_id_header: string, trust_traceparent: bool|string}, definitions: array{require_registered: bool|string}, source: array{id: ?string, region: ?string}, redaction: array{keys: list<string>, key: ?string, identifiers: string, ip: string, max_bytes: int|string, max_context_bytes: int|string}, failure: array{mode: string, log_channel: ?string}, delivery: array{mode: string, outbox: array{connection: ?string, table: string, lease_seconds: int|string, max_attempts: int|string, backoff_seconds: int|string}, deliveries_table: string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function config(): array
    {
        /** @var array{storage: array{connection: ?string, maintenance_connection: ?string}, entries: array{table: string}, integrity: array{keys: array<string, string>, current: ?string}, actor: array{guards: ?list<string>}, context: array{trust_request_id: bool|string, request_id_header: string, trust_traceparent: bool|string}, definitions: array{require_registered: bool|string}, source: array{id: ?string, region: ?string}, redaction: array{keys: list<string>, key: ?string, identifiers: string, ip: string, max_bytes: int|string, max_context_bytes: int|string}, failure: array{mode: string, log_channel: ?string}, delivery: array{mode: string, outbox: array{connection: ?string, table: string, lease_seconds: int|string, max_attempts: int|string, backoff_seconds: int|string}, deliveries_table: string}} $config */
        $config = require self::CONFIG;

        return $config;
    }
}
