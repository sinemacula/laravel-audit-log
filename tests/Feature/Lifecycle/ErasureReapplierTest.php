<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureReapplier;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Feature tests for erasing again, after a restore, the owners an erasures file
 * names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureReapplier::class)]
final class ErasureReapplierTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string When every erasure runs, unless a test moves the clock. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var string The operation every reconciliation is journalled under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000c1';

    /** @var string The code a card charge, encrypted under its actor's key, is captured under. */
    private const string CARD = 'billing.card_charged';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, bind the package's key wrapper, encrypter and reader,
     * and define the charge.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CARD)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }

    /**
     * Put the clock back and remove the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
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
     * Each owner is erased in part, accepting pending deliveries.
     *
     * @return void
     */
    public function testEachOwnerIsErasedPartiallyWithPendingAccepted(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $this->chargeCard(self::owner('42'));

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:01', 'UTC'));

        $result = $this->reapply([self::line('42'), self::line('43')]);
        $rows   = $this->rowsOf(JournalKind::ERASURE);

        self::assertSame([2, 2, 0, 0], [$result->owners, $result->erased, $result->partial, $result->refused]);
        self::assertCount(2, $rows);

        foreach ($rows as $row) {
            $payload = $row->payloadMap() ?? [];

            self::assertTrue($payload['partial']);
            self::assertTrue($payload['pending_accepted']);
            self::assertSame(1, $payload['pending_rows']);
        }
    }

    /**
     * A reapply reads each journal row once across its owners, starting from
     * the beginning twice.
     *
     * @return void
     */
    public function testAReapplyReadsEachJournalRowOnceAcrossItsOwners(): void
    {
        $owners = ['41', '42', '43', '44', '45', '46'];

        foreach ($owners as $id) {
            $this->makeSubjectKey(self::owner($id));
        }

        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000b2', HoldScope::all()->categories('unrelated'), self::authority(), HoldBasis::LEGAL_CLAIM, null);
        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000b3', HoldScope::all()->categories('unrelated'), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        $before = count($this->journalRows());
        $after  = $this->journalPageStarts(fn (): ReapplyResult => $this->reapply(array_map(self::line(...), $owners)));

        self::assertGreaterThan(0, $before);
        self::assertCount(count($owners), $this->rowsOf(JournalKind::ERASURE));
        self::assertSame([0, ...range($before + 1, $before + count($owners) - 1), 0], $after);
    }

    /**
     * An owner erased in part leaves the restore unreconciled.
     *
     * @return void
     */
    public function testAPartiallyErasedOwnerLeavesTheRestoreUnreconciled(): void
    {
        $this->chargeCard(self::owner('42'));

        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000b1', HoldScope::all()->categories('billing'), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        $result = $this->reapply([self::line('42'), self::line('43')]);

        self::assertFalse($result->reconciled);
        self::assertSame([2, 1, 1, 0], [$result->owners, $result->erased, $result->partial, $result->rejected]);
        self::assertNull($result->reconciliationId);
        self::assertSame([], $this->rowsOf(JournalKind::RESTORE_RECONCILED));
        self::assertCount(2, $this->rowsOf(JournalKind::ERASURE));
    }

    /**
     * Once every owner is fully erased, the reconciliation is journalled with
     * the anchor's head.
     *
     * @return void
     */
    public function testAllOwnersErasedJournalsTheReconciliationWithTheAnchoredHead(): void
    {
        app()->instance(CheckpointAnchor::class, (new RecordingAnchor)->holdInstead(7, str_repeat('d', 64)));

        $this->makeSubjectKey(self::owner('42'), null, 'billing');
        $this->eraseByHand(self::owner('44'));

        $path   = $this->file([self::line('42'), self::line('43'), self::line('44')]);
        $result = app(ErasureReapplier::class)->reapply(self::OPERATION, $path, self::authority());
        $rows   = $this->rowsOf(JournalKind::RESTORE_RECONCILED);

        self::assertTrue($result->reconciled);
        self::assertSame([3, 2, 1], [$result->owners, $result->erased, $result->alreadyErased]);
        self::assertSame([7, str_repeat('d', 64)], [$result->anchoredSequence, $result->anchoredDigest]);
        self::assertCount(1, $rows);
        self::assertSame([$rows[0]->id, self::OPERATION], [$result->reconciliationId, $rows[0]->operationId]);
        self::assertSame(['App\Models\User', '7', 'case.reapply'], [$rows[0]->authorityType, $rows[0]->authorityId, $rows[0]->reason]);
        self::assertSame([
            'already_erased'    => 1,
            'anchored_digest'   => str_repeat('d', 64),
            'anchored_sequence' => 7,
            'erased'            => 2,
            'file_sha256'       => hash_file('sha256', $path),
            'owners'            => 3,
        ], self::sorted($rows[0]->payloadMap() ?? []));
    }

    /**
     * Without an anchor that reports its head, the reconciliation names no
     * anchored head.
     *
     * @return void
     */
    public function testWithoutDiscoveryTheAnchoredHeadIsNull(): void
    {
        $first = $this->reapply([self::line('42')]);

        app()->instance(CheckpointAnchor::class, (new RecordingAnchor(false))->holdInstead(7, str_repeat('d', 64)));

        $second = $this->reapply([self::line('43')]);

        foreach ([$first, $second] as $result) {
            self::assertTrue($result->reconciled);
            self::assertSame([null, null], [$result->anchoredSequence, $result->anchoredDigest]);
        }

        foreach ($this->rowsOf(JournalKind::RESTORE_RECONCILED) as $row) {
            self::assertSame([null, null], [($row->payloadMap() ?? [])['anchored_sequence'], ($row->payloadMap() ?? [])['anchored_digest']]);
        }
    }

    /**
     * A line naming no owner is rejected and counted, and the restore left
     * unreconciled.
     *
     * @return void
     */
    public function testAMalformedLineIsCounted(): void
    {
        $result = $this->reapply([
            self::line('42'),
            'not json',
            '["App\\\Models\\\User","43"]',
            '{"type":"App\\\Models\\\User","id":"44","tenant":"t"}',
            '{"type":"App\\\Models\\\User"}',
            '{"type":7,"id":"45"}',
            '{"type":"App\\\Models\\\User","id":4.5}',
            '{"type":"App\\\Models\\\User","id":{"n":"46"}}',
            '{"type":"App\\\Models\\\User","id":"4\u00007"}',
            '{"type":"App\\\Models\\\User","id":"' . str_repeat('x', 1100) . '"}',
            '',
            '   ',
            '{"type":"App\\\Models\\\User","id":48}',
        ]);

        self::assertFalse($result->reconciled);
        self::assertSame([2, 2, 9], [$result->owners, $result->erased, $result->rejected]);
        self::assertSame([], $this->rowsOf(JournalKind::RESTORE_RECONCILED));
        self::assertTrue(app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner('48'))?->isErasure());
    }

    /**
     * An owner named twice, the second time with an integer id, is erased once.
     *
     * @return void
     */
    public function testAnOwnerNamedTwiceIsErasedOnce(): void
    {
        $result = $this->reapply([self::line('42'), '{"type":"App\\\Models\\\User","id":42}', self::line('42')]);

        self::assertTrue($result->reconciled);
        self::assertSame([1, 1, 0], [$result->owners, $result->erased, $result->rejected]);
        self::assertCount(1, $this->rowsOf(JournalKind::ERASURE));
    }

    /**
     * A file changed during the run fails it, and the erasures made stand.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFileChangedDuringTheRunFails(): void
    {
        $padding = array_fill(0, 1100, str_repeat(' ', 1000));
        $path    = $this->file([self::line('42'), ...$padding, self::line('43')]);

        try {
            app(ErasureReapplier::class)->reapply(self::OPERATION, $path, self::authority(), static function (Reference $owner) use ($path): ErasureResult {
                file_put_contents($path, self::line('44') . "\n", FILE_APPEND);

                return app(Eraser::class)->erase(Str::uuid7()->toString(), $owner, self::authority(), true, true);
            });

            self::fail('Expected the run to fail.');
        } catch (\UnexpectedValueException $failure) {
            self::assertSame('The erasures file changed while its owners were erased again; the restore is not reconciled.', $failure->getMessage());
        }

        self::assertSame([], $this->rowsOf(JournalKind::RESTORE_RECONCILED));
        self::assertCount(3, $this->rowsOf(JournalKind::ERASURE));
    }

    /**
     * A file of too many non-blank lines is refused before any owner is erased.
     *
     * @return void
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function testAFileOfTooManyLinesIsRefusedBeforeAnyErasure(): void
    {
        $path    = $this->longFile('', str_repeat('x', 99), self::line('42'));
        $failure = new \LogicException('No owner is erased.');

        try {
            app(ErasureReapplier::class)->reapply(self::OPERATION, $path, self::authority(), static fn (Reference $owner): never => throw $failure);

            self::fail('Expected the file to be refused.');
        } catch (\InvalidArgumentException $refusal) {
            self::assertSame('An erasures file holds at most 100000 lines that are not blank.', $refusal->getMessage());
        }

        $result = app(ErasureReapplier::class)->reapply(
            self::OPERATION,
            $this->longFile(self::line('42'), str_repeat(' ', 99), self::line('43')),
            self::authority(),
            static fn (Reference $owner): ErasureResult => ErasureResult::alreadyErased(Str::uuid7()->toString(), 'f', 'k'),
        );

        self::assertSame([2, 0], [$result->owners, $result->rejected]);
    }

    /**
     * A refused owner is counted and the run goes on.
     *
     * @return void
     */
    public function testARefusedOwnerIsCountedAndTheRunGoesOn(): void
    {
        app()->bind(FieldEncrypter::class, RecordingFieldEncrypter::class);

        $result = $this->reapply([self::line('42'), self::line('43')]);

        self::assertFalse($result->reconciled);
        self::assertSame([2, 0, 2], [$result->owners, $result->erased, $result->refused]);
        self::assertSame([], $this->journalRows());
    }

    /**
     * Any failure but a refusal stops the run.
     *
     * @return void
     *
     * @throws \RuntimeException
     * @throws \Throwable
     */
    public function testAnotherFailureStopsTheRun(): void
    {
        $erased  = [];
        $path    = $this->file([self::line('42'), self::line('43')]);
        $failure = new \RuntimeException('The lock wait timed out.');

        try {
            app(ErasureReapplier::class)->reapply(self::OPERATION, $path, self::authority(), static function (Reference $owner) use (&$erased, $failure): never {
                $erased[] = $owner->id;

                throw $failure;
            });

            self::fail('Expected the run to fail.');
        } catch (\RuntimeException $failure) {
            self::assertSame('The lock wait timed out.', $failure->getMessage());
        }

        self::assertSame(['42'], $erased);
        self::assertSame([], $this->journalRows());
    }

    /**
     * An anchor that cannot be read fails the run before the reconciliation is
     * journalled.
     *
     * @return void
     */
    public function testAnUnavailableAnchorFailsBeforeJournalling(): void
    {
        app()->instance(CheckpointAnchor::class, (new RecordingAnchor)->failing());

        try {
            $this->reapply([self::line('42')]);

            self::fail('Expected the run to fail.');
        } catch (\RuntimeException $failure) {
            self::assertSame('The anchor is unavailable.', $failure->getMessage());
        }

        self::assertSame([], $this->rowsOf(JournalKind::RESTORE_RECONCILED));
        self::assertCount(1, $this->rowsOf(JournalKind::ERASURE));
    }

    /**
     * The erasure given is asked for each owner and its outcome counted.
     *
     * @return void
     */
    public function testTheErasureGivenErasesEachOwner(): void
    {
        $asked  = [];
        $path   = $this->file([self::line('42'), self::line('43')]);
        $result = app(ErasureReapplier::class)->reapply(self::OPERATION, $path, self::authority(), static function (Reference $owner) use (&$asked): ErasureResult {
            $asked[] = $owner->id;

            return ErasureResult::alreadyErased(Str::uuid7()->toString(), 'f', 'k')->withRecorded($owner->id === '42');
        });

        self::assertSame(['42', '43'], $asked);
        self::assertSame([2, 0, 2, false, true], [$result->owners, $result->erased, $result->alreadyErased, $result->recorded, $result->reconciled]);
    }

    /**
     * The sequence each journal page read starts after, in order, while the
     * work runs.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult  $work
     * @return list<int>
     */
    private function journalPageStarts(\Closure $work): array
    {
        $pattern = sprintf('/\bfrom\s+["`]?%s["`]?\s+where\s+["`]?sequence["`]?\s*>\s*\?/i', preg_quote(LifecycleTables::journalTable(), '/'));
        $starts  = new \ArrayObject;

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use ($pattern, $starts): void {
            if (preg_match($pattern, $query->sql) !== 1) {
                return;
            }

            $starts->append((int) $query->bindings[0]);
        });

        $work();

        /** @var list<int> */
        return $starts->getArrayCopy();
    }

    /**
     * Erase again the owners the lines name, under the test's operation and
     * authority.
     *
     * @param  list<string>  $lines
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult
     */
    private function reapply(array $lines): ReapplyResult
    {
        return app(ErasureReapplier::class)->reapply(Str::uuid7()->toString(), $this->file($lines), self::authority());
    }

    /**
     * The verified journal's rows of the kind, in sequence order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\JournalRow>
     */
    private function rowsOf(JournalKind $kind): array
    {
        $rows = array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === $kind->value);

        return array_values(array_map(static fn (array $row): JournalRow => JournalRow::fromRow($row, true), $rows));
    }

    /**
     * Capture a charge of a card the actor owns, encrypted under the actor's
     * key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return void
     */
    private function chargeCard(Reference $actor): void
    {
        AuditLog::event(self::CARD)->by($actor)->withProperties(['amount' => '12.00', 'card' => '4242'])->record();
    }

    /**
     * Write a file of the lines given, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'erasures-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * Write a file of the first line, the most filler lines a reapply reads,
     * and the last line.
     *
     * @param  string  $first
     * @param  string  $filler
     * @param  string  $last
     * @return string
     */
    private function longFile(string $first, string $filler, string $last): string
    {
        $path   = $this->file([$first]);
        $handle = fopen($path, 'ab');

        self::assertIsResource($handle);

        $chunk = str_repeat($filler . "\n", 1000);

        for ($written = 0; $written < ErasureReapplier::MAX_LINES; $written += 1000) {
            fwrite($handle, $chunk);
        }

        fwrite($handle, $last . "\n");
        fclose($handle);

        return $path;
    }

    /**
     * The map with its keys sorted, so it compares whatever order it was
     * written in.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $map
     * @return array<array-key, mixed>
     */
    private static function sorted(array $map): array
    {
        ksort($map);

        return $map;
    }

    /**
     * A line of the erasures file naming the user of the id.
     *
     * @param  string  $id
     * @return string
     */
    private static function line(string $id): string
    {
        return (string) json_encode(['type' => 'App\Models\User', 'id' => $id]);
    }

    /**
     * The user of the id, as an owner.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(string $id): Reference
    {
        return Reference::of('App\Models\User', $id);
    }

    /**
     * The authority every reapply is asked for on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.reapply');
    }
}
