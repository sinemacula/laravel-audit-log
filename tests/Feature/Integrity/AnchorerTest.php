<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Filesystem\Filesystem as Files;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\RecordsStorageStatements;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the anchorer, on whichever engine the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Anchorer::class)]
final class AnchorerTest extends TestCase
{
    use RecordsStorageStatements, SealsEntries;

    /** @var string When each sealer runs. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When each anchorer runs. */
    private const string ANCHORED_AT = '2026-11-01 13:05:00';

    /** @var string The faked disk a disk anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string A secret of a ring that does not hold the key the seals name. */
    private const string OTHER_SECRET = 'audit-log anchorer test other key 0123456789';

    /** @var list<string> The columns written after a seal row is inserted. */
    private const array ANCHOR_COLUMNS = ['anchor', 'anchor_receipt', 'anchored_at', 'anchor_error_class'];

    /**
     * Freeze the sealer's clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Delete the faked disk's files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        (new Files)->deleteDirectory(storage_path('framework/testing/disks/' . self::DISK));

        parent::tearDown();
    }

    /**
     * With no anchor configured a pass makes no statement and no call, and says
     * no anchor is configured.
     *
     * @return void
     */
    public function testTheNullAnchorCostsNoStatement(): void
    {
        $this->sealSeals(2);

        $statements = $this->recordStatements();
        $result     = $this->anchorer(new NullAnchor)->anchorPending();

        self::assertSame([], $statements->getArrayCopy());
        self::assertFalse($result->isConfigured());
        self::assertSame(0, $result->anchoredCount());
        self::assertNull($this->seals()[0]['anchored_at']);
    }

    /**
     * Every pending seal is anchored, in sequence order, each once.
     *
     * @return void
     */
    public function testAnchorsEachPendingSealInSequenceOrder(): void
    {
        $this->sealSeals(3);

        $anchor = new RecordingAnchor;
        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(3, $result->anchoredCount());
        self::assertSame(3, $result->lastAnchored());
        self::assertFalse($result->isStopped());
        self::assertSame(['latest', 'anchor', 'anchor', 'anchor'], $anchor->calls());
        self::assertSame(array_combine([1, 2, 3], array_column($this->seals(), 'seal_digest')), $anchor->held());
    }

    /**
     * The anchor, the receipt, when the seal was anchored and no error are kept
     * beside the seal.
     *
     * @return void
     */
    public function testTheReceiptIsKeptWithTheSeal(): void
    {
        $this->sealSeals(1);

        $this->anchorer(new RecordingAnchor)->anchorPending();

        $seal = $this->seals()[0];

        self::assertSame(RecordingAnchor::NAME, $seal['anchor']);
        self::assertSame(['digest' => $seal['seal_digest'], 'sequence' => 1], self::receiptOf($seal));
        self::assertSame('2026-11-01T13:05:00.000000Z', StoredTime::fromStorage((string) $seal['anchored_at']));
        self::assertNull($seal['anchor_error_class']);
    }

    /**
     * A seal anchored under the anchor's name is not anchored again.
     *
     * @return void
     */
    public function testAnAnchoredSealIsNotAnchoredAgain(): void
    {
        $this->sealSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();

        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(0, $result->anchoredCount());
        self::assertNull($result->lastAnchored());
        self::assertSame(['latest', 'anchor', 'anchor', 'latest'], $anchor->calls());
    }

    /**
     * An unavailable anchor stops the pass and keeps its failure's class on the
     * first seal, unreported: the command decides what to say.
     *
     * @return void
     */
    public function testAnUnavailableAnchorIsRecordedNotReported(): void
    {
        $handler = new RecordingExceptionHandler;

        $this->sealSeals(2);

        app()->instance(ExceptionHandler::class, $handler);
        Event::fake();

        $anchor = (new RecordingAnchor)->failing();
        $result = $this->anchorer($anchor)->anchorPending();
        $seals  = $this->seals();

        self::assertSame(\RuntimeException::class, $result->unavailableClass());
        self::assertSame(1, $result->waitingFrom());
        self::assertFalse($result->isAlarm());
        self::assertSame(['latest', 'anchor'], $anchor->calls());
        self::assertSame([\RuntimeException::class, null], array_column($seals, 'anchor_error_class'));
        self::assertSame([null, null], array_column($seals, 'anchored_at'));
        self::assertSame([null, null], array_column($seals, 'anchor'));
        self::assertSame([], $handler->reports());
        Event::assertNothingDispatched();
    }

    /**
     * A later pass retries a seal an unavailable anchor left unanchored, and
     * clears its error once it is anchored.
     *
     * @return void
     */
    public function testALaterRunRetriesAnUnanchoredSeal(): void
    {
        $this->sealSeals(2);

        $anchor = (new RecordingAnchor)->failing();

        $this->anchorer($anchor)->anchorPending();

        $result = $this->anchorer($anchor->recovering())->anchorPending();
        $seals  = $this->seals();

        self::assertSame(2, $result->anchoredCount());
        self::assertNull($result->unavailableClass());
        self::assertSame([null, null], array_column($seals, 'anchor_error_class'));
        self::assertSame([RecordingAnchor::NAME, RecordingAnchor::NAME], array_column($seals, 'anchor'));
    }

    /**
     * Rows of `[name]`: names the `anchor` column cannot hold.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedNames(): iterable
    {
        yield from [
            'empty'                  => [''],
            'one character too many' => [str_repeat('a', 65)],
            'invalid UTF-8'          => ["disk:\xff"],
        ];
    }

    /**
     * An anchor whose name the `anchor` column cannot hold is unavailable,
     * before any seal is read or any call reaches it.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideMalformedNames')]
    public function testAnAnchorWithAMalformedNameIsUnavailable(string $name): void
    {
        $this->sealSeals(1);

        $inner      = new RecordingAnchor;
        $statements = $this->recordStatements();
        $result     = $this->anchorer(self::named($name, $inner))->anchorPending();

        self::assertSame(\UnexpectedValueException::class, $result->unavailableClass());
        self::assertNull($result->waitingFrom());
        self::assertSame([], $statements->getArrayCopy());
        self::assertSame([], $inner->calls());
    }

    /**
     * A name of 64 characters, multibyte ones counted as one each, is the
     * longest the column holds, and is anchored under.
     *
     * @return void
     */
    public function testANameOfSixtyFourCharactersIsAccepted(): void
    {
        $this->sealSeals(1);

        $name   = str_repeat('é', 64);
        $result = $this->anchorer(self::named($name, new RecordingAnchor))->anchorPending();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame($name, $this->seals()[0]['anchor']);
    }

    /**
     * A failure of an anonymous class is kept by its debug type, never its
     * file, and never its message.
     *
     * @return void
     */
    public function testAnAnonymousFailureIsNamedWithoutItsFile(): void
    {
        $this->sealSeals(1);

        $failure = new class ('Down at /var/www/secret.php') extends \RuntimeException {};
        $result  = $this->anchorer((new RecordingAnchor)->failing($failure))->anchorPending();

        self::assertSame('RuntimeException@anonymous', $result->unavailableClass());
        self::assertSame('RuntimeException@anonymous', $this->seals()[0]['anchor_error_class']);
    }

    /**
     * A failure's class longer than the column is cut to 191 characters, never
     * inside a character, so it stays valid UTF-8 on every engine.
     *
     * @return void
     */
    public function testALongFailureClassIsCutToTheColumnByCharacter(): void
    {
        $this->sealSeals(1);

        $failure = \Mockery::namedMock('Tests\Long\\' . str_repeat('é', 190), \RuntimeException::class);
        $result  = $this->anchorer((new RecordingAnchor)->failing($failure))->anchorPending();
        $kept    = 'Tests\Long\\' . str_repeat('é', 180);

        self::assertSame(191, mb_strlen($kept));
        self::assertSame($kept, $result->unavailableClass());
        self::assertSame($kept, $this->seals()[0]['anchor_error_class']);
    }

    /**
     * A remote success whose local write failed is given the identical receipt
     * on the next pass, and anchors with no conflict.
     *
     * @return void
     */
    public function testARemoteSuccessWithAFailedLocalWriteRecoversWithTheSameReceipt(): void
    {
        $this->sealSeals(1);

        $failed = false;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use (&$failed): void {
            if (!$failed && str_starts_with(strtolower($query), 'update') && str_contains($query, 'anchor_receipt')) {
                $failed = true;

                throw new \DomainException('The receipt cannot be written.');
            }
        });

        $anchor = new RecordingAnchor;
        $first  = $this->anchorer($anchor)->anchorPending();
        $digest = $this->seals()[0]['seal_digest'];

        self::assertSame(\DomainException::class, $first->unavailableClass());
        self::assertSame([1 => $digest], $anchor->held());
        self::assertNull($this->seals()[0]['anchored_at']);

        $second = $this->anchorer($anchor)->anchorPending();
        $seal   = $this->seals()[0];

        self::assertSame(1, $second->anchoredCount());
        self::assertNull($second->conflict());
        self::assertSame(['latest', 'anchor', 'latest', 'anchor'], $anchor->calls());
        self::assertSame(['digest' => $digest, 'sequence' => 1], self::receiptOf($seal));
        self::assertNull($seal['anchor_error_class']);
    }

    /**
     * An anchor that holds another digest for a seal's sequence stops the pass,
     * keeps the conflict's class on that seal, and anchors no later seal.
     *
     * @return void
     */
    public function testAConflictStopsThePass(): void
    {
        $this->sealSeals(2);

        $anchor = (new RecordingAnchor)->holdInstead(1, str_repeat('e', 64));
        $result = $this->anchorer($anchor)->anchorPending();
        $seals  = $this->seals();

        self::assertSame(['sequence' => 1, 'sealId' => $seals[0]['id']], $result->conflict());
        self::assertTrue($result->isAlarm());
        self::assertSame(0, $result->anchoredCount());
        self::assertSame(['latest', 'anchor'], $anchor->calls());
        self::assertSame([AnchorConflictException::class, null], array_column($seals, 'anchor_error_class'));
        self::assertSame([null, null], array_column($seals, 'anchored_at'));
        self::assertNull($this->progress(IntegrityProgress::ANCHOR_LAST_FAILURE));
    }

    /**
     * Rows of `[what is changed, the finding]`: a stored seal edited so it no
     * longer verifies, or whose key the ring no longer holds.
     *
     * @return iterable<string, array{0: \Closure(self): void, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideTamperedSeals(): iterable
    {
        yield from [
            'stored digest edited' => [static function (self $test): void {
                $test->editFirstSeal(['seal_digest' => str_repeat('f', 64)]);
            }, Finding::SEAL_DIGEST],
            'a field edited' => [static function (self $test): void {
                $test->editFirstSeal(['sealed_at' => '2026-11-01 13:00:01']);
            }, Finding::SEAL_DIGEST],
            'signature edited' => [static function (self $test): void {
                $test->editFirstSeal(['signature' => str_repeat('a', 64)]);
            }, Finding::SEAL_SIGNATURE],
            'signature malformed' => [static function (self $test): void {
                $test->editFirstSeal(['signature' => 'not-a-signature']);
            }, Finding::SEAL_MALFORMED],
            'a field malformed' => [static function (self $test): void {
                $test->editFirstSeal(['members_digest' => 'malformed']);
            }, Finding::SEAL_MALFORMED],
            'key removed' => [static function (self $test): void {
                $test->useRing(['k-other' => self::OTHER_SECRET], 'k-other');
            }, Finding::SEAL_KEY],
        ];
    }

    /**
     * A seal that does not verify is never anchored: only the head is asked
     * for, no seal column is written and no later seal is anchored.
     *
     * @param  \Closure(self): void  $tamper
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     */
    #[DataProvider('provideTamperedSeals')]
    public function testATamperedSealIsNeverAnchored(\Closure $tamper, Finding $finding): void
    {
        $this->sealSeals(2);

        $tamper($this);

        $anchor = new RecordingAnchor;
        $result = $this->anchorer($anchor)->anchorPending();
        $seals  = $this->seals();

        self::assertSame(['sequence' => 1, 'sealId' => $seals[0]['id'], 'finding' => $finding], $result->refusal());
        self::assertSame(['latest'], $anchor->calls());
        self::assertSame([null, null], array_column($seals, 'anchored_at'));
        self::assertSame([null, null], array_column($seals, 'anchor_error_class'));
    }

    /**
     * A seal whose id is malformed is refused without naming the id.
     *
     * @return void
     */
    public function testASealWithAMalformedIdIsRefusedWithoutIt(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() === 'pgsql') {
            self::markTestSkipped('PostgreSQL\'s uuid column cannot hold a malformed id.');
        }

        $this->sealSeals(1);
        $this->editFirstSeal(['id' => 'NOT-A-UUID']);

        $result = $this->anchorer(new RecordingAnchor)->anchorPending();

        self::assertSame(['sequence' => 1, 'sealId' => null, 'finding' => Finding::SEAL_MALFORMED], $result->refusal());
    }

    /**
     * A seal whose sequence is not an integer, as only SQLite's dynamic typing
     * can store, is refused as sequence 0, since it has none to name.
     *
     * @return void
     */
    public function testASealWithAMalformedSequenceIsRefusedAsSequenceZero(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores text in an integer column.');
        }

        $this->sealSeals(1);
        $this->editFirstSeal(['sequence' => 'first']);

        $result = $this->anchorer(new RecordingAnchor)->anchorPending();

        self::assertSame(['sequence' => 0, 'sealId' => $this->seals()[0]['id'], 'finding' => Finding::SEAL_MALFORMED], $result->refusal());
    }

    /**
     * A disk anchor's name is its location, so an anchor moved to another path
     * anchors every seal again there, under its own name.
     *
     * @return void
     */
    public function testMovingTheAnchorReanchorsEverySeal(): void
    {
        $this->sealSeals(2);

        $disk   = Storage::fake(self::DISK);
        $first  = $this->diskAnchor($disk, 'anchors-a');
        $second = $this->diskAnchor($disk, 'anchors-b');

        self::assertSame(2, $this->anchorer($first)->anchorPending()->anchoredCount());
        self::assertSame(0, $this->anchorer($first)->anchorPending()->anchoredCount());
        self::assertSame(2, $this->anchorer($second)->anchorPending()->anchoredCount());
        self::assertSame([$second->name(), $second->name()], array_column($this->seals(), 'anchor'));
        self::assertNotSame($first->name(), $second->name());
        self::assertCount(4, $disk->allFiles('anchors-b'));
    }

    /**
     * Anchor columns written onto a fresh seal never keep it from being
     * anchored, since the anchor's own answer decides.
     *
     * @return void
     */
    public function testReceiptColumnsOnAFreshSealNeverKeepItFromTheAnchor(): void
    {
        $this->sealSeals(1);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();
        $this->sealOneMore();

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('sequence', 2)->update([
            'anchor'         => RecordingAnchor::NAME,
            'anchor_receipt' => '{"forged":true}',
            'anchored_at'    => '2026-11-01 13:04:00',
        ]);

        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame(2, $result->lastAnchored());
        self::assertSame(array_combine([1, 2], array_column($this->seals(), 'seal_digest')), $anchor->held());
    }

    /**
     * Below the anchor's head, a seal with no receipt is anchored again, and
     * one whose receipt names another anchor is left as it is.
     *
     * @return void
     */
    public function testBelowTheHeadOnlyALostReceiptIsAnchoredAgain(): void
    {
        $this->sealSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('sequence', 1)->update(['anchor' => 'elsewhere']);
        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('sequence', 2)->update(['anchored_at' => null, 'anchor_receipt' => null]);

        $result = $this->anchorer($anchor)->anchorPending();
        $seals  = $this->seals();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame(2, $result->lastAnchored());
        self::assertSame(['elsewhere', RecordingAnchor::NAME], array_column($seals, 'anchor'));
        self::assertNotNull($seals[1]['anchor_receipt']);
    }

    /**
     * An anchor that cannot report its head starts after the last seal progress
     * records under its name, and from the first seal otherwise.
     *
     * @return void
     */
    public function testAnAnchorThatCannotDiscoverStartsAfterItsLastProgress(): void
    {
        $this->sealSeals(3);

        $anchor = new RecordingAnchor(false);

        self::assertSame(3, $this->anchorer($anchor)->anchorPending()->anchoredCount());

        $this->sealOneMore();

        $again = $this->anchorer($anchor)->anchorPending();

        self::assertSame(1, $again->anchoredCount());
        self::assertSame(4, $again->lastAnchored());

        $elsewhere = ['sequence' => 4, 'anchor' => 'elsewhere', 'anchored_at' => '2026-11-01T13:05:00.000000Z'];

        app(IntegrityProgress::class)->put(IntegrityProgress::ANCHOR_LAST, $elsewhere, FrozenClock::at(self::ANCHORED_AT)->now());

        self::assertSame(4, $this->anchorer($anchor)->anchorPending()->anchoredCount());
        self::assertNotContains('latest', $anchor->calls());
    }

    /**
     * An anchor whose discovery fails is given the seals after the last one
     * progress records, so a failure in discovery alone never stops anchoring.
     *
     * @return void
     */
    public function testAFailingDiscoveryFallsBackToProgress(): void
    {
        $this->sealSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();
        $this->sealOneMore();

        $failing = new class ($anchor) implements CheckpointAnchor {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $inner
             */
            public function __construct(

                /** The anchor every call but discovery reaches. */
                private readonly RecordingAnchor $inner,
            ) {}

            /**
             * The inner anchor's name.
             *
             * @return string
             */
            #[\Override]
            public function name(): string
            {
                return $this->inner->name();
            }

            /**
             * Anchor through the inner anchor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @return array<string, scalar|null>
             */
            #[\Override]
            public function anchor(SealSummary $seal): array
            {
                return $this->inner->anchor($seal);
            }

            /**
             * Confirm through the inner anchor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @param  array<string, scalar|null>  $receipt
             * @return bool
             */
            #[\Override]
            public function confirms(SealSummary $seal, array $receipt): bool
            {
                return $this->inner->confirms($seal, $receipt);
            }

            /**
             * Whether the anchor can report its head: it claims it can.
             *
             * @return bool
             */
            #[\Override]
            public function supportsDiscovery(): bool
            {
                return true;
            }

            /**
             * Fail to report the head.
             *
             * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function latest(): ?AnchoredHead
            {
                throw new \RuntimeException('The anchor cannot list.');
            }
        };

        $result = $this->anchorer($failing)->anchorPending();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame(3, $result->lastAnchored());
    }

    /**
     * A seal below sequence 1 is outside the chain: it is refused after the
     * pass and never stops the chain's seals being anchored.
     *
     * @return void
     */
    public function testASealOutsideTheChainIsRefusedAfterThePass(): void
    {
        $this->sealSeals(1);

        $phantom = ['id' => '01932b4e-9000-7000-8000-00000000abcd', 'sequence' => 0, 'anchor' => RecordingAnchor::NAME, 'anchored_at' => '2026-11-01 13:04:00'] + $this->seals()[0];

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->insert($phantom);

        $anchor = new RecordingAnchor;
        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame(['sequence' => 0, 'sealId' => '01932b4e-9000-7000-8000-00000000abcd', 'finding' => Finding::SEAL_MALFORMED], $result->refusal());
        self::assertSame([1], array_keys($anchor->held()));
    }

    /**
     * A seal outside the chain is refused at the sequence it is stored at, the
     * lowest first.
     *
     * @return void
     */
    public function testASealOutsideTheChainIsRefusedAtItsSequence(): void
    {
        $this->sealSeals(1);

        $table = DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());

        $table->insert(['id' => '01932b4e-9000-7000-8000-00000000abcd', 'sequence' => -1] + $this->seals()[0]);
        $table->insert(['id' => '01932b4e-9000-7000-8000-00000000abce', 'sequence' => -2] + $this->seals()[0]);

        $result = $this->anchorer(new RecordingAnchor)->anchorPending();

        self::assertSame(['sequence' => -2, 'sealId' => '01932b4e-9000-7000-8000-00000000abce', 'finding' => Finding::SEAL_MALFORMED], $result->refusal());
    }

    /**
     * A seal outside the chain whose sequence is not an integer, as only SQLite
     * stores in an integer column, is refused as sequence 0.
     *
     * @return void
     */
    public function testASealOutsideTheChainAtAFractionIsRefusedAsSequenceZero(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores a fraction in an integer column.');
        }

        $this->sealSeals(1);

        $phantom = ['id' => '01932b4e-9000-7000-8000-00000000abcd', 'sequence' => -0.5] + $this->seals()[0];

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->insert($phantom);

        $result = $this->anchorer(new RecordingAnchor)->anchorPending();

        self::assertSame(['sequence' => 0, 'sealId' => '01932b4e-9000-7000-8000-00000000abcd', 'finding' => Finding::SEAL_MALFORMED], $result->refusal());
    }

    /**
     * A pass anchors at most its batch, the lost receipts below the anchor's
     * head and the seals after it together.
     *
     * @return void
     */
    public function testAPassAnchorsAtMostItsBatch(): void
    {
        $this->sealSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();
        $this->sealOneMore();

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('sequence', 1)->update(['anchored_at' => null]);
        app(ConfigRepository::class)->set('audit-log.integrity.anchor.batch', 1);

        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame(1, $result->lastAnchored());
    }

    /**
     * Rows of `[the last anchoring progress records]`: progress that is
     * malformed, below the chain or of another anchor, holding no seal.
     *
     * @return iterable<string, array{0: array<string, scalar|null>}>
     */
    public static function provideProgressHoldingNoSeal(): iterable
    {
        yield from [
            'a malformed sequence'   => [['sequence' => 'x', 'anchor' => RecordingAnchor::NAME]],
            'a sequence below 1'     => [['sequence' => -5, 'anchor' => RecordingAnchor::NAME]],
            'sequence 0'             => [['sequence' => 0, 'anchor' => RecordingAnchor::NAME]],
            'another anchor\'s name' => [['sequence' => 3, 'anchor' => 'elsewhere']],
            'no name'                => [['sequence' => 3]],
        ];
    }

    /**
     * Progress that holds no seal gives an anchor that cannot discover every
     * seal in the chain from 1, and never one outside it.
     *
     * @param  array<string, scalar|null>  $progress
     * @return void
     */
    #[DataProvider('provideProgressHoldingNoSeal')]
    public function testProgressHoldingNoSealGivesEverySealInTheChain(array $progress): void
    {
        $this->sealSeals(3);

        $anchor = new RecordingAnchor(false);

        $this->anchorer($anchor)->anchorPending();

        $phantom = ['id' => '01932b4e-9000-7000-8000-00000000abcd', 'sequence' => 0] + $this->seals()[0];

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->insert($phantom);
        app(IntegrityProgress::class)->put(IntegrityProgress::ANCHOR_LAST, $progress, FrozenClock::at(self::ANCHORED_AT)->now());

        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(3, $result->anchoredCount());
        self::assertSame(0, $result->refusal()['sequence'] ?? null);
    }

    /**
     * A seal outside the chain with no receipt below the head is no lost
     * receipt: it is refused after the pass, and later seals still anchor.
     *
     * @return void
     */
    public function testASealOutsideTheChainIsNoLostReceipt(): void
    {
        $this->sealSeals(1);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();
        $this->sealOneMore();

        $unanchored = ['id' => '01932b4e-9000-7000-8000-00000000abcd', 'sequence' => 0, 'anchor' => null, 'anchor_receipt' => null, 'anchored_at' => null];
        $phantom    = $unanchored + $this->seals()[0];

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->insert($phantom);

        $result = $this->anchorer($anchor)->anchorPending();

        self::assertSame(1, $result->anchoredCount());
        self::assertSame(2, $result->lastAnchored());
        self::assertSame(0, $result->refusal()['sequence'] ?? null);
    }

    /**
     * A pass of an empty anchor never reads lost receipts below a head it has
     * not got.
     *
     * @return void
     */
    public function testAPassOfAnEmptyAnchorReadsNoLostReceipts(): void
    {
        $this->sealSeals(1);

        $statements = [];

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        $this->anchorer(new RecordingAnchor)->anchorPending();

        $table = IntegrityTables::checkpointsTable();
        $reads = array_values(array_filter($statements, static fn (string $sql): bool => str_starts_with(strtolower($sql), 'select') && str_contains($sql, $table)));

        self::assertCount(2, $reads);
    }

    /**
     * A pass reads by the sequence and anchoring indexes, never an `OR` across
     * the anchor columns, so it never reads the anchored seals.
     *
     * @return void
     */
    public function testAPassReadsByTheSequenceAndAnchoringIndexes(): void
    {
        $this->sealSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();

        $statements = [];

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        $this->anchorer($anchor)->anchorPending();

        $reads = array_values(array_filter($statements, static fn (string $sql): bool => str_contains($sql, IntegrityTables::checkpointsTable())));

        self::assertCount(3, $reads);

        foreach ($reads as $sql) {
            self::assertStringNotContainsString(' or ', strtolower($sql), $sql);
            self::assertStringNotContainsString('"anchor" <>', $sql, $sql);
        }
    }

    /**
     * Rows of `[receipt]`: receipts that are not a map of string keys to
     * scalars or `null`, cannot be encoded, or are one byte over the bound.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideRefusedReceipts(): iterable
    {
        yield from [
            'a list'               => [['a', 'b']],
            'a nested map'         => [['path' => ['a' => 'b']]],
            'an object value'      => [['path' => new \stdClass]],
            'invalid UTF-8'        => [['path' => "\xff"]],
            'a float not a number' => [['size' => NAN]],
            'one byte over'        => [['blob' => str_repeat('a', Anchorer::MAX_RECEIPT_BYTES - 10)]],
        ];
    }

    /**
     * A receipt that is no map of string keys to scalars or `null`, cannot be
     * encoded or exceeds 4096 bytes makes the anchor unavailable.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $receipt
     * @return void
     */
    #[DataProvider('provideRefusedReceipts')]
    public function testAnOversizedReceiptIsUnavailable(array $receipt): void
    {
        $this->sealSeals(1);

        $result = $this->anchorer(self::giving($receipt))->anchorPending();
        $seal   = $this->seals()[0];

        self::assertSame(\UnexpectedValueException::class, $result->unavailableClass());
        self::assertSame(\UnexpectedValueException::class, $seal['anchor_error_class']);
        self::assertNull($seal['anchor_receipt']);
        self::assertNull($seal['anchored_at']);
    }

    /**
     * Rows of `[receipt, its JSON]`: receipts kept as given, the longest one
     * the bound allows included.
     *
     * @return iterable<string, array{0: array<string, scalar|null>, 1: string}>
     */
    public static function provideKeptReceipts(): iterable
    {
        yield from [
            'an empty map'         => [[], '{}'],
            'every kind of scalar' => [['a' => 'x/y', 'b' => 2, 'c' => 1.0, 'd' => true, 'e' => null], '{"a":"x/y","b":2,"c":1.0,"d":true,"e":null}'],
            'exactly at the bound' => [['blob' => str_repeat('a', Anchorer::MAX_RECEIPT_BYTES - 11)], '{"blob":"' . str_repeat('a', Anchorer::MAX_RECEIPT_BYTES - 11) . '"}'],
        ];
    }

    /**
     * A receipt that is a map of string keys to scalars or `null` within the
     * bound is kept as JSON, every value's type kept.
     *
     * @param  array<string, scalar|null>  $receipt
     * @param  string  $json
     * @return void
     */
    #[DataProvider('provideKeptReceipts')]
    public function testAReceiptWithinTheBoundIsKept(array $receipt, string $json): void
    {
        $this->sealSeals(1);

        $this->sealsAnchoredBy(self::giving($receipt), 1);

        $kept = (string) $this->seals()[0]['anchor_receipt'];

        $expected = json_decode($json, true);
        $actual   = json_decode($kept, true);

        self::assertIsArray($expected);
        self::assertIsArray($actual);
        self::assertSame($expected, $actual);
        self::assertSame(self::typesOf($expected), self::typesOf($actual));
    }

    /**
     * A pass anchors at most the batch, and the next pass goes on from there.
     *
     * @return void
     */
    public function testStopsAtTheBatch(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.anchor.batch', 2);

        $this->sealSeals(3);

        $anchor = new RecordingAnchor;

        $first  = $this->anchorer($anchor)->anchorPending();
        $second = $this->anchorer($anchor)->anchorPending();

        self::assertSame(2, $first->anchoredCount());
        self::assertSame(2, $first->lastAnchored());
        self::assertSame(1, $second->anchoredCount());
        self::assertSame(3, $second->lastAnchored());
    }

    /**
     * Anchoring updates exactly the four anchor columns, and a failure only its
     * error column, so no other seal column is ever written.
     *
     * @return void
     */
    public function testOnlyTheAnchorColumnsAreWritten(): void
    {
        $this->sealSeals(2);

        $statements = $this->recordStatements();
        $anchor     = new RecordingAnchor;

        $anchor->holdInstead(2, str_repeat('e', 64));

        $this->anchorer($anchor)->anchorPending();

        $updates = self::updatedColumns($statements->getArrayCopy());

        self::assertSame([self::ANCHOR_COLUMNS, ['anchor_error_class']], $updates);
    }

    /**
     * Progress records the last seal a pass anchored, and the seal, the class
     * and the time of the last failure, which a later anchoring leaves.
     *
     * @return void
     */
    public function testProgressRecordsTheLastAnchorAndFailure(): void
    {
        $this->sealSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();

        self::assertSame(['sequence' => 2, 'anchor' => RecordingAnchor::NAME, 'anchored_at' => '2026-11-01T13:05:00.000000Z'], $this->progress(IntegrityProgress::ANCHOR_LAST));
        self::assertNull($this->progress(IntegrityProgress::ANCHOR_LAST_FAILURE));

        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();
        $this->anchorer($anchor->failing())->anchorPending();

        $failure = ['sequence' => 3, 'class' => \RuntimeException::class, 'at' => '2026-11-01T13:05:00.000000Z'];

        self::assertSame($failure, $this->progress(IntegrityProgress::ANCHOR_LAST_FAILURE));
        self::assertSame(['sequence' => 2, 'anchor' => RecordingAnchor::NAME, 'anchored_at' => '2026-11-01T13:05:00.000000Z'], $this->progress(IntegrityProgress::ANCHOR_LAST));

        $this->anchorer($anchor->recovering())->anchorPending();

        self::assertSame(['sequence' => 3, 'anchor' => RecordingAnchor::NAME, 'anchored_at' => '2026-11-01T13:05:00.000000Z'], $this->progress(IntegrityProgress::ANCHOR_LAST));
        self::assertSame($failure, $this->progress(IntegrityProgress::ANCHOR_LAST_FAILURE));
    }

    /**
     * A pass with nothing pending records no progress.
     *
     * @return void
     */
    public function testAPassWithNothingPendingRecordsNoProgress(): void
    {
        $result = $this->anchorer(new RecordingAnchor)->anchorPending();

        self::assertSame(0, $result->anchoredCount());
        self::assertNull($this->progress(IntegrityProgress::ANCHOR_LAST));
    }

    /**
     * Change columns of the first seal, as someone who can write to the
     * database could.
     *
     * @param  array<string, ?string>  $columns
     * @return void
     */
    private function editFirstSeal(array $columns): void
    {
        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('id', $this->seals()[0]['id'])->update($columns);
    }

    /**
     * Store one entry a minute apart from 12:00 and seal each on its own, so
     * there are that many seals, by sequence.
     *
     * @param  int  $count
     * @return void
     */
    private function sealSeals(int $count): void
    {
        for ($index = 0; $index < $count; $index++) {
            $this->storeEntryAt(sprintf('2026-11-01 12:%02d:00', $index));
            $this->sealer()->seal();
        }

        self::assertCount($count, $this->seals());
    }

    /**
     * Store one more entry, at 12:30, and seal it on its own.
     *
     * @return void
     */
    private function sealOneMore(): void
    {
        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();
    }

    /**
     * Anchor with the anchor, asserting how many seals were anchored.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  int  $count
     * @return void
     */
    private function sealsAnchoredBy(CheckpointAnchor $anchor, int $count): void
    {
        $result = $this->anchorer($anchor)->anchorPending();

        self::assertNull($result->unavailableClass());
        self::assertSame($count, $result->anchoredCount());
    }

    /**
     * An anchorer of the anchor, built from the container's collaborators on a
     * clock frozen when anchoring runs.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchorer
     */
    private function anchorer(CheckpointAnchor $anchor): Anchorer
    {
        $clock = FrozenClock::at(self::ANCHORED_AT);

        return new Anchorer($anchor, app(SealSigner::class), app(AnchorSettings::class), app(IntegrityProgress::class), $clock, app(DatabaseManager::class));
    }

    /**
     * A disk anchor on the faked disk, under the path given.
     *
     * @param  \Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @param  string  $path
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     */
    private function diskAnchor(Filesystem $disk, string $path): DiskAnchor
    {
        return new DiskAnchor($disk, self::DISK, $path, app(SealSettings::class)->logId());
    }

    /**
     * The progress recorded under the name, read afresh.
     *
     * @param  string  $name
     * @return ?array<string, scalar|null>
     *
     * @phpstan-impure
     */
    private function progress(string $name): ?array
    {
        return app(IntegrityProgress::class)->get($name);
    }

    /**
     * The columns each update of the seals table sets, in order.
     *
     * @param  array<int, string>  $statements
     * @return list<list<string>>
     */
    private static function updatedColumns(array $statements): array
    {
        $updates = [];

        foreach ($statements as $statement) {
            if (!str_starts_with(strtolower($statement), 'update') || !str_contains($statement, IntegrityTables::checkpointsTable())) {
                continue;
            }

            preg_match('/ set (.+) where /i', $statement, $set);
            preg_match_all('/[`"]([a-z_]+)[`"]\s*=/', $set[1] ?? '', $columns);

            $updates[] = $columns[1];
        }

        return $updates;
    }

    /**
     * The receipt kept beside the seal, decoded, by key.
     *
     * @param  array<string, scalar|null>  $seal
     * @return array<string, scalar|null>
     */
    private static function receiptOf(array $seal): array
    {
        /** @var array<string, scalar|null> $receipt */
        $receipt = json_decode((string) $seal['anchor_receipt'], true, 512, JSON_THROW_ON_ERROR);

        ksort($receipt);

        return $receipt;
    }

    /**
     * The type of each value, by key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, string>
     */
    private static function typesOf(array $values): array
    {
        return array_map(get_debug_type(...), $values);
    }

    /**
     * An anchor that hands every call to another, under the name given.
     *
     * @param  string  $name
     * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $inner
     * @return \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor
     */
    private static function named(string $name, RecordingAnchor $inner): CheckpointAnchor
    {
        return new readonly class ($name, $inner) implements CheckpointAnchor {
            /**
             * Constructor.
             *
             * @param  string  $name
             * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $inner
             */
            public function __construct(

                /** The name given. */
                private string $name,

                /** The anchor every call is handed to. */
                private RecordingAnchor $inner,
            ) {}

            /**
             * The name given.
             *
             * @return string
             */
            #[\Override]
            public function name(): string
            {
                return $this->name;
            }

            /**
             * Hand the summary to the inner anchor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @return array<string, scalar|null>
             */
            #[\Override]
            public function anchor(SealSummary $seal): array
            {
                return $this->inner->anchor($seal);
            }

            /**
             * Ask the inner anchor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @param  array<string, scalar|null>  $receipt
             * @return bool
             */
            #[\Override]
            public function confirms(SealSummary $seal, array $receipt): bool
            {
                return $this->inner->confirms($seal, $receipt);
            }

            /**
             * Ask the inner anchor.
             *
             * @return bool
             */
            #[\Override]
            public function supportsDiscovery(): bool
            {
                return $this->inner->supportsDiscovery();
            }

            /**
             * Ask the inner anchor.
             *
             * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
             */
            #[\Override]
            public function latest(): ?AnchoredHead
            {
                return $this->inner->latest();
            }
        };
    }

    /**
     * An anchor that gives the receipt for every summary, whatever it is, as an
     * anchor breaking its contract would.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $receipt
     * @return \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor
     */
    private static function giving(array $receipt): CheckpointAnchor
    {
        return new readonly class ($receipt) implements CheckpointAnchor {
            /**
             * Constructor.
             *
             * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
             *
             * @param  array<array-key, mixed>  $receipt
             */
            public function __construct(

                /** The receipt every summary is given. */
                private array $receipt,
            ) {}

            /**
             * The anchor's name.
             *
             * @return string
             */
            #[\Override]
            public function name(): string
            {
                return 'giving';
            }

            /**
             * The receipt given, whatever it is.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @return array<string, scalar|null>
             */
            #[\Override]
            public function anchor(SealSummary $seal): array
            {
                /** @var array<string, scalar|null> */
                return $this->receipt;
            }

            /**
             * Never confirms.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @param  array<string, scalar|null>  $receipt
             * @return bool
             */
            #[\Override]
            public function confirms(SealSummary $seal, array $receipt): bool
            {
                return false;
            }

            /**
             * Cannot discover.
             *
             * @return bool
             */
            #[\Override]
            public function supportsDiscovery(): bool
            {
                return false;
            }

            /**
             * Holds no head.
             *
             * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
             */
            #[\Override]
            public function latest(): ?AnchoredHead
            {
                return null;
            }
        };
    }
}
