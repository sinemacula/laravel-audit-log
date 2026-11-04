<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\Rewrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for rewrapping the owners' keys onto the current wrapping key,
 * and rotating them, on whichever engine the suite runs against: every live or
 * superseded key under another wrapping key rewrapped, its data key unchanged;
 * erased keys never touched; one journal row per batch listing each key before
 * and after; rotation superseding every live key, so the next write opens a
 * generation; a key that fails its signature or does not unwrap skipped and
 * named, never rewrapped; a key changed behind the lock never overwritten; a
 * reader seeing one whole wrapping or the other; bounded batches; the run's
 * boundary frozen at its start; and a dry run writing nothing.
 *
 * Keys are made under a ring of one wrapping key, `k1`, before the ring gains
 * `k2` as its current key, through the key creator or signed and stored by
 * hand, and owners are erased by hand, so neither the encrypter nor the eraser
 * is relied on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Rewrapper::class)]
final class RewrapperTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string When every run starts. */
    private const string NOW = '2026-11-04 10:00:00.123456';

    /** @var string The operation every run runs under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The first wrapping key's secret. */
    private const string FIRST_SECRET = 'first wrapping secret, 32 bytes!';

    /** @var string The second wrapping key's secret. */
    private const string SECOND_SECRET = 'second wrapping secret, 32 bytes';

    /** @var bool Whether a hook's work is running, so its own statements run no hook. */
    private bool $hooking = false;

    /**
     * Freeze the clock and wrap under `k1` alone.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->ring(false);
    }

    /**
     * Roll back any transaction a test left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Every live key under another wrapping key is rewrapped onto the current
     * one, bound to its own row, its data key unchanged and its state kept; a
     * key already under the current key is left as it was.
     *
     * @return void
     */
    public function testEveryKeyNotUnderTheCurrentKeyIsRewrapped(): void
    {
        $made = [$this->makeSubjectKey(self::owner(1)), $this->makeSubjectKey(self::owner(1), null, 'billing'), $this->makeSubjectKey(self::owner(2))];

        $this->ring(true);

        [$current] = $this->makeSubjectKey(self::owner(3));

        $result = $this->rewrap();
        $stored = $this->storedSubjectKeys();

        foreach ($made as [$key, $dataKey]) {
            self::assertSame('k2', $stored[$key->id]->wrapKeyId, $key->id);
            self::assertNotSame($key->wrappedKey, $stored[$key->id]->wrappedKey, $key->id);
            self::assertSame(KeyState::LIVE, $stored[$key->id]->state, $key->id);
            self::assertSame($dataKey, $this->dataKeyOf($stored[$key->id]), $key->id);
        }

        self::assertEquals($current, $stored[$current->id]);
        self::assertSame([3, 0, 0, 1], [$result->rewrapped, $result->rotated, $result->skipped, $result->batches]);
        self::assertSame(RewrapStatus::COMPLETE, $result->status);
        self::assertSame('k2', $result->wrapKeyId);
        self::assertTrue($result->committed);
        self::assertFalse($result->dryRun);
        self::assertFalse($result->rotate);
    }

    /**
     * A superseded key under another wrapping key is rewrapped too, and stays
     * superseded.
     *
     * @return void
     */
    public function testSupersededKeysAreRewrappedToo(): void
    {
        [$key, $dataKey] = $this->makeSubjectKey(self::owner(1));

        $this->supersede($key);
        $this->ring(true);

        $result = $this->rewrap();
        $stored = $this->storedSubjectKeys()[$key->id];

        self::assertSame(KeyState::SUPERSEDED, $stored->state);
        self::assertSame('k2', $stored->wrapKeyId);
        self::assertSame($dataKey, $this->dataKeyOf($stored));
        self::assertSame([1, 0], [$result->rewrapped, $result->rotated]);
    }

    /**
     * An erased key holds no wrapped key and is never touched, by a rewrap or a
     * rotation, and is never counted.
     *
     * @return void
     */
    public function testErasedKeysAreNeverTouched(): void
    {
        $this->makeSubjectKey(self::owner(1));
        $this->eraseByHand(self::owner(1));
        $this->makeSubjectKey(self::owner(2));
        $this->ring(true);

        $erased = array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->state === KeyState::ERASED);
        $result = $this->rewrap(true);

        self::assertCount(1, $erased);
        self::assertEquals($erased, array_intersect_key($this->storedSubjectKeys(), $erased));
        self::assertSame([1, 1, 0], [$result->rewrapped, $result->rotated, $result->skipped]);
    }

    /**
     * Each batch appends one `rewrap` row naming the operation and the
     * authority, listing the run's id, whether it rotates, each key it changed,
     * by id, with its state, wrapped key digest and wrapping key before and
     * after, and the keys it skipped.
     *
     * @return void
     */
    public function testTheJournalRowListsEachKeysBeforeAndAfter(): void
    {
        [$first]  = $this->makeSubjectKey(self::owner(1));
        [$second] = $this->makeSubjectKey(self::owner(2));

        $this->ring(true);
        $this->rewrap(true);

        $stored = $this->storedSubjectKeys();
        $rows   = $this->journalRows();
        $row    = JournalRow::fromRow($rows[0], true);
        $keys   = [$first, $second];

        usort($keys, static fn (SubjectKeyRow $left, SubjectKeyRow $right): int => strcmp($left->id, $right->id));

        $entries = array_map(static fn (SubjectKeyRow $key): array => [
            'key_id' => $key->id,
            'before' => ['state' => 'live', 'wrapped_digest' => hash('sha256', (string) $key->wrappedKey), 'wrap_key_id' => 'k1'],
            'after'  => ['state' => 'superseded', 'wrapped_digest' => hash('sha256', (string) $stored[$key->id]->wrappedKey), 'wrap_key_id' => 'k2'],
        ], $keys);

        self::assertCount(1, $rows);
        self::assertSame(JournalKind::REWRAP, $row->kind);
        self::assertSame(self::OPERATION, $row->operationId);
        self::assertSame(['App\Models\User', '7', 'case.review', 'app:ticket-123'], [$row->authorityType, $row->authorityId, $row->reason, $row->externalReference]);
        self::assertSame(CanonicalEncoder::encode(['run_id' => self::OPERATION, 'rotate' => true, 'keys' => $entries, 'skipped' => []]), $row->payload);
    }

    /**
     * Rotation supersedes every live key in the statement that rewraps it, and
     * a key already under the current key keeps its wrapped key; the next write
     * of each unit then opens its next generation.
     *
     * @return void
     */
    public function testRotateSupersedesLiveKeysAndTheNextWriteOpensAGeneration(): void
    {
        [$old] = $this->makeSubjectKey(self::owner(1));

        $this->ring(true);

        [$current] = $this->makeSubjectKey(self::owner(2));

        $updates = $this->updatesOfTheKeys();
        $result  = $this->rewrap(true);
        $stored  = $this->storedSubjectKeys();

        self::assertSame([KeyState::SUPERSEDED, 'k2'], [$stored[$old->id]->state, $stored[$old->id]->wrapKeyId]);
        self::assertSame([KeyState::SUPERSEDED, $current->wrappedKey, 'k2'], [$stored[$current->id]->state, $stored[$current->id]->wrappedKey, $stored[$current->id]->wrapKeyId]);
        self::assertSame([1, 2, 0], [$result->rewrapped, $result->rotated, $result->skipped]);
        self::assertTrue($result->rotate);
        self::assertCount(2, $updates);

        foreach ($updates as $sql) {
            self::assertStringContainsString('state', $sql);
        }

        [$next] = $this->makeSubjectKey(self::owner(1));

        self::assertSame(2, $next->generation);
        self::assertSame(KeyState::LIVE, $next->state);
    }

    /**
     * A key whose wrapped key does not unwrap under its own context, or whose
     * wrapping key the wrapper does not hold, is skipped, named in the result
     * and the batch's row, and left as it was; the run is partial and the rest
     * are rewrapped.
     *
     * @return void
     */
    public function testAKeyThatFailsToUnwrapIsSkippedAndReported(): void
    {
        [$moved]   = $this->makeSubjectKey(self::owner(1));
        [$foreign] = $this->makeSubjectKey(self::owner(2));
        [$good]    = $this->makeSubjectKey(self::owner(3));

        $this->updateKey($moved, ['wrapped_key' => $good->wrappedKey]);
        $this->updateKey($foreign, ['wrap_key_id' => 'k0']);
        $this->ring(true);

        $before = $this->storedSubjectKeys();
        $result = $this->rewrap();
        $after  = $this->storedSubjectKeys();
        $ids    = [$moved->id, $foreign->id];

        sort($ids, SORT_STRING);

        self::assertSame(RewrapStatus::PARTIAL, $result->status);
        self::assertSame([1, 2], [$result->rewrapped, $result->skipped]);
        self::assertSame($ids, $result->skippedKeyIds);
        self::assertEquals($before[$moved->id], $after[$moved->id]);
        self::assertEquals($before[$foreign->id], $after[$foreign->id]);
        self::assertSame('k2', $after[$good->id]->wrapKeyId);
        self::assertSame($ids, JournalRow::fromRow($this->journalRows()[0], true)->payloadMap()['skipped'] ?? null);
    }

    /**
     * With rotation, a key already under the current wrapping key is unwrapped
     * too: one whose wrapped key does not open is skipped and named, left live
     * and as it was, never superseded or counted as rotated.
     *
     * @return void
     */
    public function testARotatedKeyUnderTheCurrentKeyThatDoesNotUnwrapIsSkipped(): void
    {
        [$corrupt] = $this->makeSubjectKey(self::owner(1));
        [$good]    = $this->makeSubjectKey(self::owner(2));

        $this->updateKey($corrupt, ['wrapped_key' => 'invalid-ciphertext']);

        $before = $this->storedSubjectKeys();
        $result = $this->rewrap(true);
        $after  = $this->storedSubjectKeys();

        self::assertSame(RewrapStatus::PARTIAL, $result->status);
        self::assertSame([0, 1, 1], [$result->rewrapped, $result->rotated, $result->skipped]);
        self::assertSame([$corrupt->id], $result->skippedKeyIds);
        self::assertEquals($before[$corrupt->id], $after[$corrupt->id]);
        self::assertSame(KeyState::LIVE, $after[$corrupt->id]->state);
        self::assertSame(KeyState::SUPERSEDED, $after[$good->id]->state);
    }

    /**
     * A new wrapped key that does not unwrap to the same data key, as a faulty
     * wrapper gives, never replaces the stored one, which is the only copy: the
     * key is skipped and named, and left as it was.
     *
     * @return void
     */
    public function testANewWrappedKeyThatDoesNotOpenIsNeverStored(): void
    {
        [$key] = $this->makeSubjectKey(self::owner(1));

        $this->ring(true);

        $local = app(LocalKeyWrapper::class);

        $this->app?->instance(KeyWrapper::class, new class ($local) implements KeyWrapper {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper  $local
             */
            public function __construct(

                /** The package's own wrapper, which the double wraps another key with and unwraps through. */
                private readonly LocalKeyWrapper $local,
            ) {}

            /**
             * The local ring's current key.
             *
             * @return string
             */
            #[\Override]
            public function currentKeyId(): string
            {
                return $this->local->currentKeyId();
            }

            /**
             * Another data key wrapped in place of the one given.
             *
             * @param  string  $dataKey
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             */
            #[\Override]
            public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string
            {
                return $this->local->wrap(strrev($dataKey), $wrapKeyId, $context);
            }

            /**
             * The local ring's unwrapping.
             *
             * @param  string  $wrapped
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             */
            #[\Override]
            public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string
            {
                return $this->local->unwrap($wrapped, $wrapKeyId, $context);
            }
        });

        $before = $this->storedSubjectKeys();
        $result = $this->rewrap();

        self::assertSame(RewrapStatus::PARTIAL, $result->status);
        self::assertSame([0, 1, [$key->id]], [$result->rewrapped, $result->skipped, $result->skippedKeyIds]);
        self::assertEquals($before, $this->storedSubjectKeys());
    }

    /**
     * A key skipped by a row whose id is not a UUID, as a tampered row may hold
     * escape sequences or invalid UTF-8, is counted and never named: not in the
     * result, nor the batch's row, which counts it apart.
     *
     * @return void
     */
    public function testASkippedKeyWithoutAUuidIsCountedButNeverNamed(): void
    {
        $driver = $this->keyConnection()->getDriverName();

        if ($driver === 'pgsql') {
            self::markTestSkipped('PostgreSQL\'s uuid column holds nothing but a UUID.');
        }

        [$key] = $this->makeSubjectKey(self::owner(1));

        // MySQL's column refuses invalid UTF-8, so the escape sequence alone is
        // tampered in there
        $row               = (array) $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->first();
        $row['id']         = $driver === 'sqlite' ? "\e[31mforged\xff" : "\e[31mforged";
        $row['generation'] = 2;

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->insert($row);
        $this->ring(true);

        $result  = $this->rewrap();
        $payload = JournalRow::fromRow($this->journalRows()[0], true)->payloadMap() ?? [];

        self::assertSame(RewrapStatus::PARTIAL, $result->status);
        self::assertSame([1, 1, []], [$result->rewrapped, $result->skipped, $result->skippedKeyIds]);
        self::assertSame([[], 1], [$payload['skipped'] ?? null, $payload['skipped_unnamed'] ?? null]);
    }

    /**
     * A key whose row fails its signature, or names a signing key the ring does
     * not hold, is skipped and never unwrapped or rewrapped.
     *
     * @return void
     */
    public function testAKeyThatFailsItsSignatureIsSkippedNotRewrapped(): void
    {
        [$forged]  = $this->makeSubjectKey(self::owner(1));
        [$unknown] = $this->makeSubjectKey(self::owner(2));

        $this->updateKey($forged, ['hmac' => str_repeat('f', 64)]);
        $this->updateKey($unknown, ['key_id' => 'gone']);
        $this->ring(true);

        $before = $this->storedSubjectKeys();
        $result = $this->rewrap(true);

        self::assertEquals($before, $this->storedSubjectKeys());
        self::assertSame([0, 0, 2], [$result->rewrapped, $result->rotated, $result->skipped]);
        self::assertSame(RewrapStatus::PARTIAL, $result->status);
        self::assertSame(1, $result->batches);
    }

    /**
     * A key changed behind the lock, between the batch's read and its update,
     * is never overwritten: the compare-and-set update changes nothing, the
     * batch is rolled back whole, its row is not appended, and the run fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrentWriteChangesNothingTheBatchDecided(): void
    {
        [$first]  = $this->makeSubjectKey(self::owner(1));
        [$second] = $this->makeSubjectKey(self::owner(2));

        $this->ring(true);

        $before = $this->storedSubjectKeys();
        $target = max($first->id, $second->id);

        app()->instance(KeyWrapper::class, $this->wrapperThatChanges($target, (string) $before[min($first->id, $second->id)]->wrappedKey));

        try {
            $this->rewrap();

            self::fail('Expected the batch to be rolled back.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A subject key changed while its batch was rewrapped; the batch is rolled back.', $exception->getMessage());
        }

        self::assertEquals($before, $this->storedSubjectKeys());
        self::assertSame([], $this->journalRows());
    }

    /**
     * The batches are bounded by `audit-log.privacy.rewrap_batch`: each is one
     * transaction behind the lock with one row listing at most a batch of keys,
     * walked in id order with none twice, and an empty batch after a full one
     * appends nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheBatchesAreBounded(): void
    {
        app(ConfigRepository::class)->set('audit-log.privacy.rewrap_batch', 100);

        $ids = $this->storeKeys(200);

        $this->ring(true);

        $locks  = $this->lockStatements();
        $result = $this->rewrap();
        $listed = [];

        foreach ($this->journalRows() as $stored) {
            $keys = JournalRow::fromRow($stored, true)->payloadMap()['keys'] ?? [];

            self::assertIsArray($keys);
            self::assertCount(100, $keys);

            array_push($listed, ...array_column($keys, 'key_id'));
        }

        sort($ids, SORT_STRING);

        self::assertSame($ids, $listed);
        self::assertSame([200, 2], [$result->rewrapped, $result->batches]);
        self::assertCount(3, $locks);
        self::assertCount(2, $this->journalRows());
    }

    /**
     * A dry run confirms nothing, takes no lock and writes nothing, yet counts
     * what a run would do, its skipped keys included, uncommitted.
     *
     * @return void
     */
    public function testADryRunWritesNothing(): void
    {
        [$key] = $this->makeSubjectKey(self::owner(1));
        [$bad] = $this->makeSubjectKey(self::owner(2));

        $this->updateKey($bad, ['hmac' => str_repeat('f', 64)]);
        $this->ring(true);
        $this->installationState()->delete();

        $before = $this->storedSubjectKeys();
        $lock   = (array) DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->first();
        $result = $this->rewrap(true, true);

        self::assertEquals($before, $this->storedSubjectKeys());
        self::assertSame([], $this->journalRows());
        self::assertSame($lock, (array) DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->first());
        self::assertSame(0, $this->installationState()->count());
        self::assertSame([1, 1, 1, 1], [$result->rewrapped, $result->rotated, $result->skipped, $result->batches]);
        self::assertSame([$bad->id], $result->skippedKeyIds);
        self::assertSame(KeyState::LIVE, $this->storedSubjectKeys()[$key->id]->state);
        self::assertTrue($result->dryRun);
        self::assertFalse($result->committed);
    }

    /**
     * A reader of a key being rewrapped sees one whole wrapping or the other:
     * read through the key store before and after each update of the batch, the
     * key always unwraps under the wrapping key and context its row names to
     * the same data key.
     *
     * @return void
     */
    public function testAReaderOfAKeyBeingRewrappedSeesOneWrapOrTheOther(): void
    {
        [$key, $dataKey] = $this->makeSubjectKey(self::owner(1));

        $this->ring(true);

        /** @var \ArrayObject<int, array{0: ?string, 1: string}> $reads */
        $reads = new \ArrayObject([$this->readThroughTheStore($key->id)]);

        DB::listen(function (QueryExecuted $query) use ($reads, $key): void {
            if ($this->hooking || !str_starts_with(strtolower($query->sql), 'update') || !str_contains($query->sql, KeyTables::subjectKeysTable())) {
                return;
            }

            $this->hooking = true;

            $reads->append($this->readThroughTheStore($key->id));

            $this->hooking = false;
        });

        $this->rewrap();

        $reads->append($this->readThroughTheStore($key->id));

        self::assertSame([['k1', $dataKey], ['k2', $dataKey], ['k2', $dataKey]], $reads->getArrayCopy());
    }

    /**
     * The run's boundary is frozen at its start: a key a concurrent write
     * creates once the run has begun, under the current key, is not superseded
     * by the run's rotation and stays live.
     *
     * @return void
     */
    public function testAKeyCreatedDuringTheRunIsNotSuperseded(): void
    {
        [$before] = $this->makeSubjectKey(self::owner(1));

        $this->ring(true);

        /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow> $created */
        $created = new \ArrayObject;

        DB::listen(function (QueryExecuted $query) use ($created): void {
            if ($this->hooking || $created->count() > 0 || !str_contains($query->sql, LifecycleTables::lockTable())) {
                return;
            }

            $this->hooking = true;

            CarbonImmutable::setTestNow((new CarbonImmutable(self::NOW, 'UTC'))->addSecond());

            $created->append($this->makeSubjectKey(self::owner(9))[0]);

            $this->hooking = false;
        });

        $result = $this->rewrap(true);
        $during = $created[0];

        self::assertInstanceOf(SubjectKeyRow::class, $during);

        $stored = $this->storedSubjectKeys();

        self::assertSame(KeyState::LIVE, $stored[$during->id]->state);
        self::assertSame(KeyState::SUPERSEDED, $stored[$before->id]->state);
        self::assertSame(1, $result->rotated);
    }

    /**
     * A run with nothing to rewrap commits no batch and appends no row.
     *
     * @return void
     */
    public function testARunWithNothingToRewrapAppendsNothing(): void
    {
        $this->ring(true);
        $this->makeSubjectKey(self::owner(1));

        $result = $this->rewrap();

        self::assertSame([0, 0, 0, 0], [$result->rewrapped, $result->rotated, $result->skipped, $result->batches]);
        self::assertSame(RewrapStatus::COMPLETE, $result->status);
        self::assertSame([], $this->journalRows());
    }

    /**
     * A run confirms the installation first, writing its id once on an
     * installation that lost the one the migrations seed.
     *
     * @return void
     */
    public function testARunConfirmsTheInstallation(): void
    {
        $this->installationState()->delete();

        $this->rewrap();

        self::assertSame(1, $this->installationState()->count());
    }

    /**
     * A journal that fails verification fails the run before any key is
     * changed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABrokenJournalFailsTheRun(): void
    {
        $this->makeSubjectKey(self::owner(1));
        $this->ring(true);
        $this->journalRow(JournalKind::REWRAP, ['run_id' => 'earlier', 'rotate' => false, 'keys' => [], 'skipped' => []]);
        $this->tamperJournal(1, ['reason' => 'other.reason']);

        $before = $this->storedSubjectKeys();

        try {
            $this->rewrap();

            self::fail('Expected the run to fail.');
        } catch (JournalBrokenException $exception) {
            self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        }

        self::assertEquals($before, $this->storedSubjectKeys());
        self::assertCount(1, $this->journalRows());
    }

    /**
     * Run a rewrap under the operation and authority every test uses.
     *
     * @param  bool  $rotate
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult
     *
     * @throws \Throwable
     */
    private function rewrap(bool $rotate = false, bool $dryRun = false): RewrapResult
    {
        $this->keyWrapper();

        return app(Rewrapper::class)->rewrap(self::OPERATION, new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123'), $rotate, $dryRun);
    }

    /**
     * Wrap under `k1` alone, or with `$second` under `k2` with `k1` kept to
     * unwrap.
     *
     * @param  bool  $second
     * @return void
     */
    private function ring(bool $second): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.privacy.keys', $second ? ['k1' => self::FIRST_SECRET, 'k2' => self::SECOND_SECRET] : ['k1' => self::FIRST_SECRET]);
        $config->set('audit-log.privacy.current', $second ? 'k2' : 'k1');
    }

    /**
     * The key's data key, unwrapped under the wrapping key and context its row
     * names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @return string
     */
    private function dataKeyOf(SubjectKeyRow $key): string
    {
        return $this->keyWrapper()->unwrap((string) $key->wrappedKey, (string) $key->wrapKeyId, $key->wrapContext());
    }

    /**
     * The key of the id read through the key store, as its wrapping key's id
     * and its data key.
     *
     * @param  string  $id
     * @return array{0: ?string, 1: string}
     */
    private function readThroughTheStore(string $id): array
    {
        $key = app(KeyStore::class)->byIds([$id])[$id];

        return [$key->wrapKeyId, $this->dataKeyOf($key)];
    }

    /**
     * Supersede the key by hand, keeping its wrapped key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @return void
     */
    private function supersede(SubjectKeyRow $key): void
    {
        $this->updateKey($key, ['state' => KeyState::SUPERSEDED->value]);
    }

    /**
     * Change the stored key's columns, as raw values.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  array<string, ?string>  $columns
     * @return void
     */
    private function updateKey(SubjectKeyRow $key, array $columns): void
    {
        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($columns);
    }

    /**
     * Sign and store a live key under `k1` for each of as many owners, and
     * return their ids.
     *
     * @param  int  $count
     * @return list<string>
     *
     * @throws \Random\RandomException
     */
    private function storeKeys(int $count): array
    {
        $ids = [];

        for ($owner = 1; $owner <= $count; $owner++) {
            $key = $this->signedSubjectKey(new KeyUnit(self::owner($owner), null, self::KEY_CATEGORY), 1, random_bytes(32));

            $this->insertSubjectKey($key);

            $ids[] = $key->id;
        }

        return $ids;
    }

    /**
     * The package's key wrapper, which on its first wrap changes the stored
     * wrapped key of the key given to the text given, as a write behind the
     * lock would.
     *
     * @param  string  $keyId
     * @param  string  $wrapped
     * @return \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper
     */
    private function wrapperThatChanges(string $keyId, string $wrapped): KeyWrapper
    {
        $inner  = app(LocalKeyWrapper::class);
        $change = fn () => $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $keyId)->update(['wrapped_key' => $wrapped]);

        return new readonly class ($inner, $change) implements KeyWrapper {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper  $inner
             * @param  \Closure(): int  $change
             */
            public function __construct(

                /** The wrapper every call is passed on to. */
                private LocalKeyWrapper $inner,

                /** The change made before each wrap. */
                private \Closure $change,
            ) {}

            /**
             * The inner wrapper's current key.
             *
             * @return string
             */
            #[\Override]
            public function currentKeyId(): string
            {
                return $this->inner->currentKeyId();
            }

            /**
             * Change the key first, then wrap as the inner wrapper does.
             *
             * @param  string  $dataKey
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             */
            #[\Override]
            public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string
            {
                ($this->change)();

                return $this->inner->wrap($dataKey, $wrapKeyId, $context);
            }

            /**
             * Unwrap as the inner wrapper does.
             *
             * @param  string  $wrapped
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             */
            #[\Override]
            public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string
            {
                return $this->inner->unwrap($wrapped, $wrapKeyId, $context);
            }
        };
    }

    /**
     * Every update of the subject keys table from now on, as its statement.
     *
     * @return \ArrayObject<int, string>
     */
    private function updatesOfTheKeys(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $updates */
        $updates = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($updates): void {
            if (!str_starts_with(strtolower($query->sql), 'update') || !str_contains($query->sql, KeyTables::subjectKeysTable())) {
                return;
            }

            $updates->append($query->sql);
        });

        return $updates;
    }

    /**
     * Every statement that takes the lifecycle lock from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function lockStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $locks */
        $locks = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($locks): void {
            if (!str_starts_with(strtolower($query->sql), 'update') || !str_contains($query->sql, LifecycleTables::lockTable())) {
                return;
            }

            $locks->append($query->sql);
        });

        return $locks;
    }

    /**
     * The installation id's row of the integrity state table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function installationState(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::stateTable())->where('name', InstallationIdentity::NAME);
    }

    /**
     * The owner of the number.
     *
     * @param  int  $number
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(int $number): Reference
    {
        return Reference::of('App\Models\User', (string) $number);
    }
}
