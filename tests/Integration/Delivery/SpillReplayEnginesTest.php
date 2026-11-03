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
 * Integration tests for replaying a spill on the engine the suite runs against:
 * what a real failed write left in the documented channel's real file gives one
 * row equal to what was spilled, which verifies, and a second replay adds
 * nothing. A hostile record comes back unchanged through the file and the
 * engine's own column types, a line that was altered or cut is skipped and left
 * in the file, and a line at the full size of the bound round-trips; on SQLite,
 * MySQL and PostgreSQL alike.
 *
 * It claims no coverage because its line at the bound is among the slowest
 * things in the suite: a mutant whose covering tests included it would be
 * skipped as taking too long rather than run, so the classes it passes through
 * would go without a mutation check. Their behaviour is pinned by their own
 * tests.
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

    /** @var string One secret of the integrity key ring. */
    private const string FIRST_SECRET = 'a-first-secret-of-32-bytes-long!';

    /** @var string The memory limit a line at the full size of the bound runs under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int The columns of a row, the signature included. */
    private const int COLUMN_COUNT = 36;

    /** @var int The depth a stored row is decoded to, and an envelope with its own object. */
    private const int JSON_DEPTH = 513;

    /** @var string The documented channel's file. */
    private string $file = '';

    /** @var ?string The memory limit before a test raised it. */
    private ?string $memoryLimit = null;

    /**
     * Stop the clock, keep what a report would say out of the output, and spill
     * to the documented channel, in a file of the test's own.
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
     * Undo what the test changed, then remove the file and put the clock and
     * the memory limit back.
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
     * A write the engine really refused leaves one line, which replays to one
     * row under the record's id.
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
     * A second replay finds its record stored, says so, and adds and changes
     * nothing, through the engine's own duplicate check.
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
     * One line written twice, as a rotated or copied file can hold it, is one
     * row.
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
     * Every column of the row holds what the spilled line holds, to the
     * microsecond and the signature, read back through the engine's own types.
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
     * The replayed row verifies under the signer, and changing a value in the
     * table stops it verifying, so the check is one that can fail.
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
     * Rows of `[columns in place of the captured record's]`: what the formatter
     * would rewrite, what the engines might change, and what a reader might
     * misread: `%` tokens in a value, a key and a string column; 4-byte
     * Unicode; CR and LF and the Unicode line separators; numeric-key maps;
     * JSON's own punctuation and a literal escape; a forged marker; empty
     * containers and an empty key; a NUL; the largest integers; a column's
     * trailing spaces; an imported record's fields; and nothing at all in
     * either JSON column.
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
            'an imported record'               => [['provenance' => 'imported', 'source_record_id' => 'legacy-0042', 'import_batch_id' => self::IMPORT_BATCH_ID, 'origin' => null]],
            'no JSON at all'                   => [['properties' => null, 'context' => null]],
        ];
    }

    /**
     * A hostile record stays on one physical line with no `%`, through the
     * documented channel's real file, and its row encodes to the bytes it was
     * signed over, and verifies, whatever the engine's column types do with it.
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
     * Rows of `[what is altered, what it becomes, the failure counted]`: a
     * value and a column are mismatches, a version is one this release does not
     * read, and a column added is malformed.
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
     * A line altered in the file is skipped and counted, writes no row and is
     * left where it is, and the good line beside it still replays.
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
     * A file cut part way through its last line, as a full disk or a crash
     * leaves it, gives the lines before it and counts the last as truncated,
     * never repairing it.
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
     * An unsigned spill is counted and left: it writes no row, since signing
     * editable bytes could not establish where they came from.
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
     * A signed record under an id whose row holds other captured content is the
     * engine's duplicate and the store's conflict: it is counted by the class
     * of the failure, and the row stays as it was.
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
     * A line signed under a key since removed from the ring is quarantined and
     * never re-signed, and replays once the key is back.
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
     * A file written by the documented channel replays its spills in order,
     * with every line of the file counted in its number, and another line on
     * the channel is passed over without being counted as skipped.
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
     * An envelope at the bound, made only of the character a line writes in six
     * bytes, gives the longest line a replay accepts: it goes through the
     * documented channel's real file and comes back to a row of the same bytes.
     * Compared by hash, because a failure must not try to print it.
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
     * Make a write the engine refuses, by pointing the store at the probe
     * table, and give back the record, whose spill is then in the file.
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
     * The record finalised once, its properties one string of the length given,
     * all of it the character a spill line writes in six bytes.
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
     * Raise the memory limit, so a line at the bound fails its assertions
     * rather than the engine's limit.
     *
     * @return void
     */
    private function raiseMemoryLimit(): void
    {
        $this->memoryLimit = ini_get('memory_limit') ?: null;

        ini_set('memory_limit', self::MEMORY_LIMIT);
    }

    /**
     * Restore the memory limit, as far as what the process still holds allows:
     * the pages a line scattered may not all go back at once, and a limit below
     * them is refused with a warning. An unlimited process stays so.
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
