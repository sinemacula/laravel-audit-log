<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportClassifier;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportRecordBuilder;
use SineMacula\Laravel\AuditLog\Lifecycle\SourceDigest;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\TestCase;

/**
 * Feature tests for classifying a chunk's lines as new, duplicate or conflict.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportClassifier::class)]
final class ImportClassifierTest extends TestCase
{
    /** @var string The batch every stored row came in. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var string The first key's secret. */
    private const string FIRST_SECRET = 'import classifier first key 0001';

    /** @var string The second key's secret. */
    private const string SECOND_SECRET = 'import classifier second key 002';

    /** @var \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue The catalogue every build reads. */
    private EventCatalogue $catalogue;

    /**
     * Freeze the clock, sign under the first of two keys, and give the
     * container its own catalogue.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        $this->useRing(['k1' => self::FIRST_SECRET, 'k2' => self::SECOND_SECRET], 'k1');

        $this->catalogue = new EventCatalogue;

        app()->instance(EventCatalogue::class, $this->catalogue);
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A line is new, a duplicate or a conflict against the stored rows.
     *
     * @return void
     */
    public function testNewDuplicateAndConflict(): void
    {
        $this->store(self::line(1, 'rec-1'));
        $this->store(self::line(2, 'rec-2'));

        $new       = self::line(3, 'rec-3');
        $duplicate = self::line(4, 'rec-1');
        $conflict  = self::line(5, 'rec-2', 'invoice.rejected');
        $plan      = $this->classifier()->classify($this->connection(), [$new, $duplicate, $conflict]);

        self::assertSame([$new], $plan->lines);
        self::assertSame(app(SourceDigest::class)->of($new->assertion(), 'k1'), $plan->digestOf($new));
        self::assertSame(1, $plan->duplicates);
        self::assertSame(['rec-2'], $plan->conflictIds());
    }

    /**
     * Within one chunk, a repeated line with the same digest is a duplicate.
     *
     * @return void
     */
    public function testDuplicatesWithinOneChunk(): void
    {
        $first = self::line(1, 'rec-1');
        $plan  = $this->classifier()->classify($this->connection(), [$first, self::line(2, 'rec-1'), self::line(3, 'rec-1')]);

        self::assertSame([$first], $plan->lines);
        self::assertSame(2, $plan->duplicates);
        self::assertSame([], $plan->conflictIds());
    }

    /**
     * Within one chunk, a later line with another digest is a conflict.
     *
     * @return void
     */
    public function testAConflictWithinOneChunk(): void
    {
        $first = self::line(1, 'rec-1');
        $plan  = $this->classifier()->classify($this->connection(), [$first, self::line(2, 'rec-1', 'invoice.rejected'), self::line(3, 'rec-1')]);

        self::assertSame([$first], $plan->lines);
        self::assertSame(1, $plan->duplicates);
        self::assertSame(['rec-1'], $plan->conflictIds());
    }

    /**
     * The same record id of different sources is a different identity.
     *
     * @return void
     */
    public function testEachSourceIsItsOwnIdentity(): void
    {
        $this->store(self::line(1, 'rec-1'));

        $other = self::line(2, 'rec-1', source: 'crm-us');
        $plan  = $this->classifier()->classify($this->connection(), [$other, self::line(3, 'rec-1')]);

        self::assertSame([$other], $plan->lines);
        self::assertSame(1, $plan->duplicates);
    }

    /**
     * A record id of digits is looked up as text, so it finds its row on every
     * engine.
     *
     * @return void
     */
    public function testARecordIdOfDigitsIsLookedUpAsText(): void
    {
        $this->store(self::line(1, '0042'));

        $plan = $this->classifier()->classify($this->connection(), [self::line(2, '0042'), self::line(3, '42')]);

        self::assertSame(1, $plan->duplicates);
        self::assertSame(['42'], array_map(static fn (ImportLine $line): string => $line->sourceRecordId, $plan->lines));
    }

    /**
     * A line's digest is compared under the key the stored row names.
     *
     * @return void
     */
    public function testTheDigestIsComparedUnderTheStoredRowsKey(): void
    {
        $this->store(self::line(1, 'rec-1'));
        $this->store(self::line(2, 'rec-2'));

        $this->useRing(['k1' => self::FIRST_SECRET, 'k2' => self::SECOND_SECRET], 'k2');

        $plan = $this->classifier()->classify($this->connection(), [self::line(3, 'rec-1'), self::line(4, 'rec-2', 'invoice.rejected')]);

        self::assertSame([], $plan->lines);
        self::assertSame(1, $plan->duplicates);
        self::assertSame(['rec-2'], $plan->conflictIds());
        self::assertSame('k1', $this->storedKeyOf('rec-1'));
    }

    /**
     * A stored row under a key the ring no longer holds is a conflict.
     *
     * @return void
     */
    public function testAStoredRowUnderARemovedKeyIsAConflict(): void
    {
        $this->store(self::line(1, 'rec-1'));

        $this->useRing(['k2' => self::SECOND_SECRET], 'k2');

        $plan = $this->classifier()->classify($this->connection(), [self::line(2, 'rec-1')]);

        self::assertSame([], $plan->lines);
        self::assertSame(0, $plan->duplicates);
        self::assertSame(['rec-1'], $plan->conflictIds());
    }

    /**
     * A definition changed between imports still finds the duplicate.
     *
     * @return void
     */
    public function testADefinitionChangedBetweenImportsStillFindsTheDuplicate(): void
    {
        $line = self::line(1, 'rec-1', properties: ['amount' => '1200.00', 'customer' => 'Alice']);

        $this->store($line);

        $this->catalogue->define(EventDefinition::for('invoice.approved')->category('billing')->retain('amount'));

        $plan = $this->classifier()->classify($this->connection(), [self::line(2, 'rec-1', properties: ['amount' => '1200.00', 'customer' => 'Alice'])]);

        self::assertSame(1, $plan->duplicates);
        self::assertSame([], $plan->conflictIds());
    }

    /**
     * Stored rows are read a source and 500 record ids to a statement, on the
     * writer.
     *
     * @return void
     */
    public function testTheStoredRowsAreReadAPageOfIdsAtATime(): void
    {
        $lines = array_map(static fn (int $number): ImportLine => self::line($number, 'rec-' . $number), range(1, 501));

        $lines[] = self::line(502, 'rec-1', source: 'crm-us');

        $reads = [];

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {
            if (!str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            $reads[] = count($query->bindings);
        });

        $plan = $this->classifier()->classify($this->connection(), $lines);

        self::assertSame([501, 2, 2], $reads);
        self::assertCount(502, $plan->lines);
    }

    /**
     * Configure an explicit key ring of the keys given, signing under the
     * current one.
     *
     * @param  array<string, string>  $keys
     * @param  string  $current
     * @return void
     */
    private function useRing(array $keys, string $current): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.keys', $keys);
        $config->set('audit-log.integrity.current', $current);
    }

    /**
     * Store the line's record as an import stores it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @return void
     */
    private function store(ImportLine $line): void
    {
        $digest = $this->classifier()->digestOf($line);
        $source = new ImportedSource($line->sourceId, $line->sourceRegion, $line->sourceRecordId, self::BATCH, $digest);
        $record = app(ImportRecordBuilder::class)->build($line, $source, CarbonImmutable::now(), false);

        self::assertInstanceOf(AuditRecord::class, $record);

        $this->connection()->table(EntrySettings::table())->insert(app(RowCodec::class)->encode(app(RecordFinaliser::class)->finalise($record)));
    }

    /**
     * The key the stored row of the record id names.
     *
     * @param  string  $recordId
     * @return ?string
     */
    private function storedKeyOf(string $recordId): ?string
    {
        $key = $this->connection()->table(EntrySettings::table())->where('source_record_id', $recordId)->value('key_id');

        return is_string($key) ? $key : null;
    }

    /**
     * A line approving an invoice, of the number, record id, code, source and
     * properties given.
     *
     * @param  int  $number
     * @param  string  $recordId
     * @param  string  $event
     * @param  string  $source
     * @param  array<string, string>  $properties
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(
        int $number,
        string $recordId,
        string $event = 'invoice.approved',
        string $source = 'crm-eu',
        array $properties = ['amount' => '1200.00'],
    ): ImportLine {
        return new ImportLine(
            $number,
            $source,
            null,
            $recordId,
            $event,
            '2026-10-01T09:00:00.000001Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            'finance',
            null,
            $properties,
            null,
            null,
            null,
        );
    }

    /**
     * The classifier the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportClassifier
     */
    private function classifier(): ImportClassifier
    {
        return app(ImportClassifier::class);
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
