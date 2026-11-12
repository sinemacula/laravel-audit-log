<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\TestCase;

/**
 * The largest configured envelope through encryption and the engine, on SQLite,
 * MySQL and PostgreSQL. Payloads are compared by length and hash so a failure
 * never prints them. Claims no coverage: its payloads are too slow for mutation
 * testing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EnvelopeSizeBoundTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string The memory limit the tests run under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int The ceiling of either byte budget. */
    private const int BUDGET_CEILING = 16777216;

    /** @var int What MySQL's `max_allowed_packet` defaults to: 64 MiB. */
    private const int DEFAULT_PACKET_BYTES = 67108864;

    /** @var int What the bound keeps for every column but the two JSON ones: 64 KiB. */
    private const int OTHER_COLUMNS_BYTES = 65536;

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The id of each record padded to a size. */
    private const string ID = '019a4b2e-7c10-7000-8000-00000000f00d';

    /** @var string The longest key id the ring takes, of 32 characters. */
    private const string LONGEST_KEY_ID = 'k0123456789012345678901234567890';

    /** @var string The one secret of the ring whose key id is the longest. */
    private const string SECRET = 'a-first-secret-of-32-bytes-long!';

    /** @var array<string, int> Each free-text column of the entries table, by its longest length in characters. */
    private const array WIDTHS = [
        'event'            => 191,
        'category'         => 64,
        'outcome'          => 16,
        'reason'           => 64,
        'actor_type'       => 191,
        'actor_id'         => 191,
        'subject_type'     => 191,
        'subject_id'       => 191,
        'principal_type'   => 191,
        'principal_id'     => 191,
        'tenant_type'      => 191,
        'tenant_id'        => 191,
        'credential_id'    => 191,
        'guard'            => 64,
        'session_id'       => 191,
        'request_id'       => 64,
        'trace_id'         => 32,
        'correlation_id'   => 191,
        'origin'           => 16,
        'provenance'       => 16,
        'source_id'        => 64,
        'source_region'    => 32,
        'source_record_id' => 191,
        'ip'               => 255,
        'user_agent'       => 512,
    ];

    /** @var list<string> The columns the integrity fields fill, each of a length the signer fixes. */
    private const array SIGNED_COLUMNS = ['key_id', 'hmac'];

    /** @var list<string> The fixed-length columns. */
    private const array FIXED_COLUMNS = ['id', 'import_batch_id', 'source_digest', 'occurred_at', 'recorded_at', 'record_version', 'event_version', 'integrity_version'];

    /** @var list<string> The JSON columns, each with a budget of its own. */
    private const array JSON_COLUMNS = ['context', 'properties'];

    /** @var string The memory limit before the test. */
    private string $memoryLimit = '';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure was reported to. */
    private RecordingExceptionHandler $handler;

    /** @var string The documented channel's file. */
    private string $file = '';

    /**
     * Raise the memory limit, stop the clock, keep report output quiet, and
     * spill to the documented channel in the test's own file.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->memoryLimit = ini_get('memory_limit');

        ini_set('memory_limit', self::MEMORY_LIMIT);

        $this->moveClockTo(self::NOW);

        $this->handler = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->handler);

        $file = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($file);

        $this->file = $file;

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::SPILL_CHANNEL => DocumentedSpillChannel::config($this->file),
            'audit-log.failure.log_channel'           => self::SPILL_CHANNEL,
        ]);
    }

    /**
     * Reset the clock, remove the file, and restore the memory limit as far as
     * the process allows; a limit below what it holds is refused.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        if (is_file($this->file)) {
            unlink($this->file);
        }

        parent::tearDown();

        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));
    }

    /**
     * A record filling both budgets at their ceiling survives capture,
     * encryption, the outbox and a drain, and its row verifies.
     *
     * @return void
     */
    public function testTheConfiguredMaximumSurvivesEncryptionAndTheEngine(): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set([
            'audit-log.redaction.max_bytes'         => self::BUDGET_CEILING,
            'audit-log.redaction.max_context_bytes' => self::BUDGET_CEILING,
        ]);

        $properties = self::mapOfBytes(self::BUDGET_CEILING, 'p');
        $context    = self::mapOfBytes(self::BUDGET_CEILING, 'c');

        $pending = AuditLog::event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', '42'))
            ->withProperties($properties)
            ->immediately();

        $pending->fillContext($context);

        $id = $pending->record()->id;

        self::assertSame([], $this->handler->reports());
        self::assertSame(1, $this->outboxCount());

        $payload  = $this->payloadOf($id);
        $envelope = app(StringEncrypter::class)->decryptString($payload);

        self::assertGreaterThan(2 * self::BUDGET_CEILING, strlen($envelope));
        self::assertLessThanOrEqual(EnvelopeCodec::MAX_BYTES, strlen($envelope));

        $decoded = app(EnvelopeCodec::class)->decode($envelope, $id)->toArray();

        self::assertSame(self::BUDGET_CEILING, strlen(CanonicalEncoder::encode($decoded['properties'])));
        self::assertSame(self::BUDGET_CEILING, strlen(CanonicalEncoder::encode($decoded['context'])));

        unset($payload, $decoded);

        self::assertSame([1, 0, 0, 0, 0], self::tally($this->drain()));
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());

        $row = $this->storedRow($id);

        self::assertTrue(app(RecordSigner::class)->verifies($row));
        self::assertSame(hash('sha256', $envelope), hash('sha256', CanonicalEncoder::encode($row)));
        self::assertSame(hash('sha256', CanonicalEncoder::encode($properties)), hash('sha256', CanonicalEncoder::encode($row['properties'])));
        self::assertSame(hash('sha256', CanonicalEncoder::encode($context)), hash('sha256', CanonicalEncoder::encode($row['context'])));
    }

    /**
     * An encrypted envelope at the bound fits the outbox's column and decodes
     * back to the record.
     *
     * @return void
     */
    public function testTheEncryptedMaximumFitsTheColumn(): void
    {
        $record   = $this->recordAtTheBound();
        $envelope = app(EnvelopeCodec::class)->encode($record);
        $payload  = app(StringEncrypter::class)->encryptString($envelope);

        self::assertSame(EnvelopeCodec::MAX_BYTES, strlen($envelope));

        app(Outbox::class)->insert(self::ID, $payload);

        $read = $this->payloadOf(self::ID);

        self::assertSame(strlen($payload), strlen($read));
        self::assertSame(hash('sha256', $payload), hash('sha256', $read));

        $decrypted = app(StringEncrypter::class)->decryptString($read);

        self::assertSame(hash('sha256', $envelope), hash('sha256', $decrypted));
        self::assertSame($record->hmac, app(EnvelopeCodec::class)->decode($decrypted, self::ID)->hmac);

        unset($read, $decrypted, $payload);

        self::assertSame([1, 0, 0, 0, 0], self::tally($this->drain()));

        $row = $this->storedRow(self::ID);

        self::assertTrue(app(RecordSigner::class)->verifies($row));
        self::assertSame(hash('sha256', $envelope), hash('sha256', CanonicalEncoder::encode($row)));
    }

    /**
     * An encrypted envelope at the bound fits MySQL's default packet with the
     * rest of the statement.
     *
     * @return void
     */
    public function testTheMaximumFitsMySqlsPacket(): void
    {
        $connection = $this->outboxConnection();

        if ($connection->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL refuses a statement over its packet size.');
        }

        $record  = $this->recordAtTheBound();
        $payload = app(StringEncrypter::class)->encryptString(app(EnvelopeCodec::class)->encode($record));

        self::assertLessThan(self::DEFAULT_PACKET_BYTES, strlen($payload) + 1024);

        $packet = $connection->scalar('select @@global.max_allowed_packet');

        self::assertIsNumeric($packet);
        self::assertGreaterThan(strlen($payload), (int) $packet);

        app(Outbox::class)->insert(self::ID, $payload);

        self::assertSame(hash('sha256', $payload), hash('sha256', $this->payloadOf(self::ID)));
    }

    /**
     * A bundle at the bound, attachment included, survives encryption and the
     * engine; one byte more is refused as oversize.
     *
     * @return void
     */
    public function testABundleAtTheBoundSurvivesEncryptionAndTheEngine(): void
    {
        $base     = RecordFactory::bundled();
        $codec    = app(EnvelopeCodec::class);
        $length   = EnvelopeCodec::MAX_BYTES - strlen($codec->encode($this->finalisedRecord(self::paddedBundle($base, 0))));
        $record   = $this->finalisedRecord(self::paddedBundle($base, $length));
        $envelope = $codec->encode($record);
        $id       = $record->record->id;

        self::assertSame(EnvelopeCodec::MAX_BYTES, strlen($envelope));
        self::assertNotNull($base->attachment);

        $payload = app(StringEncrypter::class)->encryptString($envelope);

        app(Outbox::class)->insert($id, $payload);

        $read = $this->payloadOf($id);

        self::assertSame(hash('sha256', $payload), hash('sha256', $read));

        unset($payload);

        $decrypted = app(StringEncrypter::class)->decryptString($read);

        unset($read);

        self::assertSame(hash('sha256', $envelope), hash('sha256', $decrypted));

        $decoded = $codec->decode($decrypted, $id);

        self::assertSame($record->hmac, $decoded->hmac);
        self::assertEquals($record->record->attachment, $decoded->record->attachment);
        self::assertSame(hash('sha256', $envelope), hash('sha256', $codec->encode($decoded)));

        unset($decrypted, $decoded, $envelope);

        $over = $this->finalisedRecord(self::paddedBundle($base, $length + 1));

        self::assertNotNull($base->attachment->members);

        self::assertLessThan(EnvelopeCodec::MAX_BYTES - strlen($base->attachment->members), strlen(CanonicalEncoder::encode($over->toArray())));

        try {
            $codec->encode($over);

            self::fail('Expected a bundle past the bound to be refused.');
        } catch (EnvelopeRejectedException $exception) {
            self::assertSame(EnvelopeFailure::OVERSIZE, $exception->failure);
            self::assertSame($id, $exception->id);
        }
    }

    /**
     * Rows of `[failure mode, fail closed, timing, spilled, throws, reports]`,
     * one per failure rule.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 3: bool, 4: bool, 5: int}>
     */
    public static function provideOverBoundPolicies(): iterable
    {
        yield from [
            'the report mode'        => ['report', false, Timing::IMMEDIATE, true, false, 1],
            'the throw mode'         => ['throw', false, Timing::IMMEDIATE, true, true, 0],
            'a fail-closed record'   => ['report', true, Timing::IMMEDIATE, true, true, 0],
            'a transactional record' => ['report', false, Timing::TRANSACTIONAL, false, true, 0],
        ];
    }

    /**
     * An envelope one byte past the bound follows its failure rule and never
     * reaches the outbox, leaving the transaction usable.
     *
     * @param  string  $mode
     * @param  bool  $failClosed
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $spills
     * @param  bool  $throws
     * @param  int  $reports
     * @return void
     */
    #[DataProvider('provideOverBoundPolicies')]
    public function testAnEnvelopeOverTheBoundFollowsThePolicy(string $mode, bool $failClosed, Timing $timing, bool $spills, bool $throws, int $reports): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.failure.mode', $mode);

        $record = $this->paddedRecord($this->padToTheBound() + 1);
        $said   = [];

        Event::listen(AuditWriteFailed::class, static function (AuditWriteFailed $event) use (&$said): void {
            $said[] = $event;
        });

        $thrown = $this->deliver($record, $timing, $failClosed);

        self::assertSame(0, $this->outboxCount());
        self::assertSame($throws, $thrown !== null);
        self::assertCount(1, $said);
        self::assertSame(self::ID, $said[0]->id);
        self::assertSame(EnvelopeRejectedException::class, $said[0]->exception);

        self::assertCount($reports, $this->handler->reports());

        clearstatcache();

        self::assertSame($spills, filesize($this->file) > 0);
    }

    /**
     * A spilled envelope past the bound replays to one row.
     *
     * @return void
     */
    public function testASpillOfAnEnvelopeOverTheBoundReplays(): void
    {
        $this->outboxModeOn();

        $this->deliver($this->paddedRecord($this->padToTheBound() + 1), Timing::IMMEDIATE, false);

        self::assertSame(0, $this->outboxCount());

        $result = app(Replayer::class)->spill($this->file, false);

        self::assertSame(1, $result->replayed());
        self::assertSame([], $result->skipped());

        $row = $this->storedRow(self::ID);

        self::assertTrue(app(RecordSigner::class)->verifies($row));
        self::assertSame(EnvelopeCodec::MAX_BYTES + 1, strlen(CanonicalEncoder::encode($row)));
    }

    /**
     * Every column at its longest, beside both JSON columns at budget, stays
     * within the bound and round-trips through the outbox.
     *
     * @return void
     */
    public function testTheBoundCoversEveryColumnAtItsLongest(): void
    {
        $this->assertTheWidthsAreTheTables();

        app(ConfigRepository::class)->set(['audit-log.integrity.keys' => [self::LONGEST_KEY_ID => self::SECRET], 'audit-log.integrity.current' => self::LONGEST_KEY_ID]);

        $fields = array_map(static fn (int $width): string => str_repeat("\x01", $width), self::WIDTHS);

        $record = $this->finalisedRecord(RecordFactory::withFields([
            ...$fields,
            'import_batch_id' => '019a4b2e-7c10-7000-8000-00000000abcd',
            'source_digest'   => str_repeat('f', 64),
            'properties'      => self::paddedMapOfBytes(self::BUDGET_CEILING),
            'context'         => self::paddedMapOfBytes(self::BUDGET_CEILING),
        ], RecordFactory::captured(id: self::ID)));

        $envelope = app(EnvelopeCodec::class)->encode($record);

        self::assertLessThanOrEqual(EnvelopeCodec::MAX_BYTES, strlen($envelope));
        self::assertLessThanOrEqual(self::OTHER_COLUMNS_BYTES, strlen($envelope) - (2 * self::BUDGET_CEILING));

        $this->enqueue($record);

        self::assertSame([1, 0, 0, 0, 0], self::tally($this->drain()));

        $row = $this->storedRow(self::ID);

        self::assertTrue(app(RecordSigner::class)->verifies($row));
        self::assertSame(hash('sha256', $envelope), hash('sha256', CanonicalEncoder::encode($row)));
    }

    /**
     * Assert every table column is named here with the width the engine
     * reports; SQLite keeps no width.
     *
     * @return void
     */
    private function assertTheWidthsAreTheTables(): void
    {
        $named = [...array_keys(self::WIDTHS), ...self::SIGNED_COLUMNS, ...self::FIXED_COLUMNS, ...self::JSON_COLUMNS];

        sort($named);

        $columns = array_keys(RowCodec::COLUMNS);

        sort($columns);

        self::assertSame($columns, $named);

        $checked = 0;

        foreach (Schema::connection(StorageConnection::name())->getColumns(EntrySettings::table()) as $column) {
            if (!array_key_exists($column['name'], self::WIDTHS) || preg_match('/\((\d+)\)/', $column['type'], $width) !== 1) {
                continue;
            }

            self::assertSame(self::WIDTHS[$column['name']], (int) $width[1], "The column {$column['name']} has another width.");

            $checked++;
        }

        self::assertSame($this->storageConnection()->getDriverName() === 'sqlite' ? 0 : count(self::WIDTHS), $checked);
    }

    /**
     * Deliver the record, inside an outbox transaction when transactional, and
     * return what was thrown or `null`; the transaction must stay usable.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @return ?\SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function deliver(AuditRecord $record, Timing $timing, bool $failClosed): ?AuditWriteFailedException
    {
        $connection = $this->outboxConnection();
        $delivery   = app(RecordDelivery::class);

        if ($timing !== Timing::TRANSACTIONAL) {
            return self::caught(static fn () => $delivery->deliver($record, $timing, null, $failClosed));
        }

        $connection->beginTransaction();

        $thrown = self::caught(static fn () => $delivery->deliver($record, $timing, null, $failClosed));

        self::assertEquals(1, $connection->scalar('select 1'));

        $connection->rollBack();

        return $thrown;
    }

    /**
     * The sanitised failure the work threw, or `null` when it threw none.
     *
     * @param  \Closure(): void  $work
     * @return ?\SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private static function caught(\Closure $work): ?AuditWriteFailedException
    {
        try {
            $work();
        } catch (AuditWriteFailedException $exception) {
            return $exception;
        }

        return null;
    }

    /**
     * The encrypted payload the outbox holds under the id.
     *
     * @param  string  $id
     * @return string
     */
    private function payloadOf(string $id): string
    {
        $payload = $this->outboxConnection()->table(DeliveryTables::outboxTable())->where('id', $id)->value('payload');

        self::assertIsString($payload);

        return $payload;
    }

    /**
     * Drain until nothing is left to claim.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, true);
    }

    /**
     * The record whose envelope is exactly the bound, finalised once.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function recordAtTheBound(): FinalisedRecord
    {
        return $this->finalisedRecord($this->paddedRecord($this->padToTheBound()));
    }

    /**
     * How long a pad makes a record's envelope exactly the bound.
     *
     * @return int
     */
    private function padToTheBound(): int
    {
        return EnvelopeCodec::MAX_BYTES - strlen(app(EnvelopeCodec::class)->encode($this->finalisedRecord($this->paddedRecord(0))));
    }

    /**
     * A record whose properties are one string of the length given.
     *
     * @param  int  $length
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function paddedRecord(int $length): AuditRecord
    {
        return RecordFactory::withFields(['properties' => ['pad' => str_repeat('a', $length)]], RecordFactory::captured(id: self::ID));
    }

    /**
     * The bulk record with its attachment and descriptor, beside a property of
     * the given length.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $base
     * @param  int  $length
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function paddedBundle(AuditRecord $base, int $length): AuditRecord
    {
        $properties = [...(array) $base->properties, 'pad' => str_repeat('a', $length)];

        return RecordFactory::withFields(['properties' => $properties, 'attachment' => $base->attachment], $base);
    }

    /**
     * A map of top-level keys whose encoding is exactly the given bytes, each
     * value short enough for capture to keep whole.
     *
     * @param  int  $bytes
     * @param  string  $prefix
     * @return array<string, string>
     */
    private static function mapOfBytes(int $bytes, string $prefix): array
    {
        $value = str_repeat('x', FieldPolicy::STRING_MAX_BYTES);
        $count = intdiv($bytes, strlen(CanonicalEncoder::encode(sprintf('%s%05d', $prefix, 0))) + strlen(CanonicalEncoder::encode($value)) + 2);
        $map   = [];

        for ($index = 0; $index < $count; $index++) {
            $map[sprintf('%s%05d', $prefix, $index)] = $value;
        }

        $map[$prefix . 'z'] = '';
        $map[$prefix . 'z'] = str_repeat('x', $bytes - strlen(CanonicalEncoder::encode($map)));

        return $map;
    }

    /**
     * A map of one key whose encoding is exactly the bytes given.
     *
     * @param  int  $bytes
     * @return array<string, string>
     */
    private static function paddedMapOfBytes(int $bytes): array
    {
        return ['pad' => str_repeat('a', $bytes - strlen(CanonicalEncoder::encode(['pad' => ''])))];
    }

    /**
     * The drain's tally: delivered, retried, failed, stale and missed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return array{0: int, 1: int, 2: int, 3: int, 4: int}
     */
    private static function tally(DrainResult $result): array
    {
        return [$result->delivered(), $result->retried(), $result->failed(), $result->stale(), $result->missed()];
    }
}
