<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\TestCase;

/**
 * Integration tests for replaying the documented channel's real spill file on
 * SQLite, MySQL and PostgreSQL. Claims no coverage: its line at the bound is
 * too slow for mutation testing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SpillReplayEnginesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The id of the record that two signed records share. */
    private const string SHARED_ID = '019a4b2e-7c10-7000-8000-00000000beef';

    /** @var string The import batch an imported record came in. */
    private const string IMPORT_BATCH_ID = '019a4b2e-7c10-7000-8000-00000000abcd';

    /** @var array<string, ?string> An imported record's columns in place of the captured record's. */
    private const array IMPORTED = [
        'provenance'       => 'imported',
        'source_record_id' => 'legacy-0042',
        'import_batch_id'  => self::IMPORT_BATCH_ID,
        'source_digest'    => '9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c',
        'origin'           => null,
    ];

    /** @var string One secret of the integrity key ring. */
    private const string FIRST_SECRET = 'a-first-secret-of-32-bytes-long!';

    /** @var string The memory limit a line at the full size of the bound runs under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int The columns of a row, the signature included. */
    private const int COLUMN_COUNT = 37;

    /** @var int The depth a stored row, and an envelope with its own object, is decoded to. */
    private const int JSON_DEPTH = 513;

    /** @var string The documented channel's file. */
    private string $file = '';

    /** @var ?string The memory limit before a test raised it. */
    private ?string $memoryLimit = null;

    /**
     * Stop the clock, keep report output quiet, and spill to the documented
     * channel in the test's own file.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $file = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($file);

        $this->file = $file;

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::SPILL_CHANNEL => DocumentedSpillChannel::config($this->file),
            'audit-log.failure.log_channel'           => self::SPILL_CHANNEL,
        ]);
    }

    /**
     * Undo the test's changes, remove the file, and restore the clock and the
     * memory limit.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeProbeTable();

        CarbonImmutable::setTestNow();

        if (is_file($this->file)) {
            unlink($this->file);
        }

        parent::tearDown();

        $this->restoreMemoryLimit();
    }

    /**
     * A write the engine refused leaves one line, which replays to one row.
     *
     * @return void
     */
    public function testASpilledRecordReplaysToOneRow(): void
    {
        $record = $this->failAWrite();

        self::assertSame(0, $this->entryCount());
        self::assertSame(1, substr_count($this->contents(), "\n"));

        $result = $this->replay();

        self::assertSame([1, 0, 0, 0, []], self::tally($result));
        self::assertSame(['line 1: replayed ' . $record->id], $result->events());
        self::assertFalse($result->hasSkippedOrFailed());
        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * A second replay finds the record stored and changes nothing, through the
     * engine's duplicate check.
     *
     * @return void
     */
    public function testReplayingTwiceAddsNothing(): void
    {
        $record = $this->failAWrite();

        $this->replay();

        $row    = CanonicalEncoder::encode($this->storedRow($record->id));
        $second = $this->replay();

        self::assertSame([1, 0, 0, 0, []], self::tally($second));
        self::assertSame(1, $this->entryCount());
        self::assertSame($row, CanonicalEncoder::encode($this->storedRow($record->id)));
    }

    /**
     * One line held twice in a file is one row.
     *
     * @return void
     */
    public function testALineHeldTwiceInAFileIsOneRow(): void
    {
        $line = self::lineOf($this->finalisedRecord());

        file_put_contents($this->file, $line . "\n" . $line . "\n");

        self::assertSame([2, 0, 0, 0, []], self::tally($this->replay()));
        self::assertSame(1, $this->entryCount());
    }

    /**
     * Every column of the row equals the spilled line, to the microsecond and
     * the signature.
     *
     * @return void
     */
    public function testTheRowEqualsTheSpilledValues(): void
    {
        $record = $this->failAWrite();

        $this->replay();

        $spilled = json_decode(self::envelopeIn($this->contents()), false, self::JSON_DEPTH);
        $stored  = $this->storedRow($record->id);

        self::assertInstanceOf(\stdClass::class, $spilled);

        $columns = get_object_vars($spilled);

        self::assertCount(self::COLUMN_COUNT, RowCodec::COLUMNS);
        self::assertCount(self::COLUMN_COUNT, $columns);

        foreach (array_keys(RowCodec::COLUMNS) as $column) {
            self::assertSame(CanonicalEncoder::encode($columns[$column]), CanonicalEncoder::encode($stored[$column]), "The column {$column} differs.");
        }
    }

    /**
     * The replayed row verifies, and changing a value in the table stops it
     * verifying.
     *
     * @return void
     */
    public function testAReplayedRowVerifies(): void
    {
        $record = $this->failAWrite();

        $this->replay();

        $signer = app(RecordSigner::class);

        self::assertTrue($signer->verifies($this->storedRow($record->id)));

        $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->update(['actor_id' => '43']);

        self::assertFalse($signer->verifies($this->storedRow($record->id)));
    }

    /**
     * Rows of `[columns in place of the captured record's]`: values the
     * formatter might rewrite, an engine might change or a reader might
     * misread.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideHostileRecords(): iterable
    {
        yield from [
            'percent tokens in values'         => [['properties' => ['a' => '%datetime%', 'b' => '%message%', 'c' => '%context.x%', 'd' => '%extra.y%', 'e' => '100%']]],
            'percent tokens in keys'           => [['properties' => ['%datetime%' => 'a', '%extra.y%' => ['%context.x%' => 'b']]]],
            'percent tokens in string columns' => [['user_agent' => 'agent %datetime% %message%', 'correlation_id' => 'app:%extra.y%']],
            '4-byte Unicode'                   => [['properties' => ["\u{1F600}" => "\u{10FFFF}"], 'context' => ['note' => "\u{1F600}"], 'user_agent' => "agent \u{1F600}"]],
            'carriage returns and line feeds'  => [['properties' => ['note' => "one\rtwo\nthree\r\nfour\n"], 'user_agent' => "one\r\ntwo"]],
            'Unicode line separators'          => [['properties' => ['note' => "one\u{2028}two\u{2029}three\u{0085}four"]]],
            'a numeric-key map out of order'   => [['properties' => [1 => 'x', 0 => 'y']]],
            'a numeric-key map of one key'     => [['properties' => [5 => 'a']]],
            'sequential numeric keys, nested'  => [['properties' => ['map' => (object) ['0' => 'a', '1' => 'b']], 'context' => ['map' => (object) ['0' => 'a']]]],
            'punctuation of JSON'              => [['properties' => ['{"}' => '}{"\\', ']' => '"}']]],
            'a literal escape of a percent'    => [['properties' => ['a' => '%', 'b' => '\%', 'c' => '\\\u0025%']]],
            'a forged marker'                  => [['properties' => ['note' => "\n" . FailureSpill::MARKER . '{"id":"forged"}' . "\n"]]],
            'empty containers'                 => [['properties' => ['list' => [], 'map' => new \stdClass, 'nested' => [[], new \stdClass]], 'context' => []]],
            'an empty key'                     => [['properties' => ['' => 'a', 'b' => ['' => 'c']]]],
            'a NUL in a JSON value'            => [['properties' => ['note' => "a\0b"]]],
            'the largest integers'             => [['properties' => ['max' => PHP_INT_MAX, 'min' => PHP_INT_MIN]]],
            'a trailing space in a column'     => [['user_agent' => 'agent   ', 'correlation_id' => 'app:ticket ']],
            'an imported record'               => [self::IMPORTED],
            'no JSON at all'                   => [['properties' => null, 'context' => null]],
        ];
    }

    /**
     * A hostile record stays on one line with no `%`, and its row encodes to
     * the signed bytes and verifies.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     */
    #[DataProvider('provideHostileRecords')]
    public function testAHostileRecordRoundTrips(array $fields): void
    {
        $record = $this->finalisedRecord(RecordFactory::withFields($fields));

        app(FailureSpill::class)->spillFinalised($record);

        $contents = $this->contents();

        self::assertSame(1, substr_count($contents, "\n"));
        self::assertStringEndsWith("\n", $contents);
        self::assertStringNotContainsString('%', $contents);
        self::assertStringNotContainsString("\r", $contents);

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replay()));

        $stored = $this->storedRow($record->record->id);

        self::assertSame(CanonicalEncoder::encode($record->toArray()), CanonicalEncoder::encode($stored));
        self::assertTrue(app(RecordSigner::class)->verifies($stored));
    }

    /**
     * Rows of `[what is altered, what it becomes, the failure counted]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideTamperedLines(): iterable
    {
        yield from [
            'a value'        => ['1200.00', '9999.00', 'signature_mismatch'],
            'a column'       => ['"outcome":"success"', '"outcome":"failure"', 'signature_mismatch'],
            'a version'      => ['"record_version":1', '"record_version":99', 'unsupported_version'],
            'a column added' => ['"key_id":"', '"added":1,"key_id":"', 'malformed'],
        ];
    }

    /**
     * An altered line is skipped, counted and left in the file, and the good
     * line beside it replays.
     *
     * @param  string  $search
     * @param  string  $replacement
     * @param  string  $failure
     * @return void
     */
    #[DataProvider('provideTamperedLines')]
    public function testATamperedLineIsSkipped(string $search, string $replacement, string $failure): void
    {
        $tampered = $this->finalisedRecord();
        $good     = $this->finalisedRecord();
        $line     = str_replace($search, $replacement, self::lineOf($tampered));

        self::assertNotSame(self::lineOf($tampered), $line);

        $contents = $line . "\n" . self::lineOf($good) . "\n";

        file_put_contents($this->file, $contents);

        $result = $this->replay();

        self::assertSame([1, 0, 0, 0, [$failure => 1]], self::tally($result));
        self::assertTrue($result->hasSkippedOrFailed());
        self::assertSame(1, $this->entryCount());
        self::assertSame($good->record->id, $this->storedRow($good->record->id)['id']);
        self::assertSame($contents, $this->contents());
    }

    /**
     * A file cut through its last line replays the lines before it and counts
     * the last as truncated.
     *
     * @return void
     */
    public function testACutLastLineIsTruncatedAndTheRestReplay(): void
    {
        $good = $this->finalisedRecord();
        $cut  = self::lineOf($this->finalisedRecord());

        file_put_contents($this->file, self::lineOf($good) . "\n" . substr($cut, 0, (int) (strlen($cut) / 2)));

        self::assertSame([1, 0, 0, 0, ['truncated' => 1]], self::tally($this->replay()));
        self::assertSame(1, $this->entryCount());
    }

    /**
     * An unsigned spill writes no row, since signing editable bytes proves
     * nothing of their origin.
     *
     * @return void
     */
    public function testAnUnsignedLineWritesNoRow(): void
    {
        app(FailureSpill::class)->spillUnsigned(RecordFactory::captured());

        self::assertSame([0, 0, 0, 0, ['unsigned' => 1]], self::tally($this->replay()));
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A signed record under an id whose row holds other content is counted as a
     * conflict, and the row is kept.
     *
     * @return void
     */
    public function testAConflictingRecordIsCountedAndTheRowKept(): void
    {
        $stored = $this->finalisedRecord(RecordFactory::captured(['amount' => '1200.00'], self::SHARED_ID));
        $other  = $this->finalisedRecord(RecordFactory::captured(['amount' => '9999.00'], self::SHARED_ID));

        $this->store()->store($stored);

        file_put_contents($this->file, self::lineOf($other) . "\n");

        $result = $this->replay();

        self::assertSame([0, 0, 1, 0, []], self::tally($result));
        self::assertSame(['line 1: failed ' . self::SHARED_ID . ' (' . RecordConflictException::class . ')'], $result->events());
        self::assertSame(1, $this->entryCount());
        self::assertSame(CanonicalEncoder::encode($stored->toArray()), CanonicalEncoder::encode($this->storedRow(self::SHARED_ID)));
    }

    /**
     * A line under a key removed from the ring is quarantined, never re-signed,
     * and replays once the key is back.
     *
     * @return void
     */
    public function testALineUnderARemovedKeyReplaysOnceTheKeyIsBack(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(['audit-log.integrity.keys' => ['k1' => self::FIRST_SECRET], 'audit-log.integrity.current' => 'k1']);

        $record = $this->finalisedRecord();

        file_put_contents($this->file, self::lineOf($record) . "\n");

        $config->set(['audit-log.integrity.keys' => ['k2' => 'a-second-secret-of-32-bytes-ok!!'], 'audit-log.integrity.current' => 'k2']);

        self::assertSame([0, 0, 0, 0, ['unknown_key' => 1]], self::tally($this->replay()));
        self::assertSame(0, $this->entryCount());

        $config->set(['audit-log.integrity.keys' => ['k1' => self::FIRST_SECRET], 'audit-log.integrity.current' => 'k1']);

        self::assertSame([1, 0, 0, 0, []], self::tally($this->replay()));
        self::assertSame($record->hmac, $this->storedRow($record->record->id)['hmac']);
    }

    /**
     * A documented channel file replays its spills in order, counting every
     * line and passing over other lines.
     *
     * @return void
     */
    public function testADocumentedChannelFileReplays(): void
    {
        $first = $this->failAWrite();

        Log::channel(self::SPILL_CHANNEL)->critical('Another line on the channel.');
        Log::channel(self::SPILL_CHANNEL)->info('A line below the channel\'s level.');

        $second = $this->failAWrite();

        self::assertSame(3, substr_count($this->contents(), "\n"));

        $result = $this->replay();

        self::assertSame([2, 0, 0, 0, []], self::tally($result));
        self::assertSame(['line 1: replayed ' . $first->id, 'line 3: replayed ' . $second->id], $result->events());
        self::assertSame(2, $this->entryCount());
    }

    /**
     * A line at the bound, of six-byte characters, round-trips through the
     * documented channel, compared by hash.
     *
     * @return void
     */
    public function testAFullSizeLineRoundTripsThroughTheDocumentedChannel(): void
    {
        $this->raiseMemoryLimit();

        $base   = strlen(app(EnvelopeCodec::class)->encode($this->finalisedOfPad(0)));
        $pad    = EnvelopeCodec::MAX_BYTES - $base;
        $record = $this->finalisedOfPad($pad);
        $hash   = hash('sha256', app(EnvelopeCodec::class)->encode($record));

        app(FailureSpill::class)->spillFinalised($record);

        unset($record);

        clearstatcache();

        self::assertSame(strlen(FailureSpill::MARKER) + EnvelopeCodec::MAX_BYTES + (5 * $pad) + 1, filesize($this->file));

        $result = $this->replay();

        self::assertSame([1, 0, 0, 0, []], self::tally($result));

        $row = $this->storedRow($this->idInEvent($result));

        self::assertTrue(app(RecordSigner::class)->verifies($row));

        $stored = CanonicalEncoder::encode($row);

        self::assertSame(EnvelopeCodec::MAX_BYTES, strlen($stored));
        self::assertSame($hash, hash('sha256', $stored));
    }

    /**
     * Make the engine refuse a write by pointing the store at the probe table,
     * and return the record now spilled.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function failAWrite(): AuditRecord
    {
        $this->pointAtProbeTable();

        $record = AuditLog::event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', '42'))
            ->withProperties(['amount' => '1200.00'])
            ->immediately()
            ->record();

        $this->removeProbeTable();

        return $record;
    }

    /**
     * Replay the documented channel's file.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     */
    private function replay(): ReplayResult
    {
        return app(Replayer::class)->spill($this->file, false);
    }

    /**
     * What the documented channel's file holds.
     *
     * @return string
     */
    private function contents(): string
    {
        $contents = file_get_contents($this->file);

        self::assertIsString($contents);

        return $contents;
    }

    /**
     * The record finalised once, its properties one string of the given length
     * of six-byte spill characters.
     *
     * @param  int  $length
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalisedOfPad(int $length): FinalisedRecord
    {
        return $this->finalisedRecord(RecordFactory::withFields(['properties' => ['pad' => str_repeat('%', $length)]], RecordFactory::captured(id: self::SHARED_ID)));
    }

    /**
     * The id the only event of the replay names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return string
     */
    private function idInEvent(ReplayResult $result): string
    {
        return substr($result->events()[0], strlen('line 1: replayed '));
    }

    /**
     * Raise the memory limit, so a line at the bound fails its assertions and
     * not the engine's limit.
     *
     * @return void
     */
    private function raiseMemoryLimit(): void
    {
        $this->memoryLimit = ini_get('memory_limit') ?: null;

        ini_set('memory_limit', self::MEMORY_LIMIT);
    }

    /**
     * Restore the memory limit as far as the process allows; a limit below what
     * it holds is refused.
     *
     * @return void
     */
    private function restoreMemoryLimit(): void
    {
        if ($this->memoryLimit === null) {
            return;
        }

        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));
    }

    /**
     * The tally's counts: replayed, would replay, failed, deferred and skipped.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return array{0: int, 1: int, 2: int, 3: int, 4: array<string, int>}
     */
    private static function tally(ReplayResult $result): array
    {
        return [$result->replayed(), $result->wouldReplay(), $result->failed(), $result->deferred(), $result->skipped()];
    }

    /**
     * The spill line of the finalised record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     */
    private static function lineOf(FinalisedRecord $record): string
    {
        return FailureSpill::line($record->toArray());
    }

    /**
     * The JSON envelope the spill line holds.
     *
     * @param  string  $contents
     * @return string
     */
    private static function envelopeIn(string $contents): string
    {
        $envelope = SpillReader::extract($contents);

        self::assertIsString($envelope);

        return $envelope;
    }
}
