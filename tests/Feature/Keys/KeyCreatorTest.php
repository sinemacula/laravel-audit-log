<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Keys\KeyCreator;
use SineMacula\Laravel\AuditLog\Keys\KeySession;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Keys\OwnerLock;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for the creation of a unit's key, on whichever engine the suite
 * runs against: the first key at generation one, none for an erased owner, a
 * reinstated owner's and a rotated unit's above their floor, a live key that
 * landed meanwhile returned rather than doubled, a race past the locks settled
 * by the unique index and a re-read, the marker read, the live key read and the
 * insert in one transaction after the lock, the data key wrapped bound to its
 * row and the row signed, and the session closed and the owner released however
 * a creation ends.
 *
 * Where a test needs another writer to act at a moment of the creation, it acts
 * as the creation is about to run its lock statement, or on SQLite, which takes
 * none, its first read inside the transaction: on MySQL and PostgreSQL from the
 * storage connection or a session of its own, committed at once, and on
 * in-memory SQLite inside the creation's own transaction, which is the storage
 * connection's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyCreator::class)]
final class KeyCreatorTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string The instant the clock is frozen at. */
    private const string NOW = '2026-11-04 10:00:00.123456';

    /** @var string The owner every test makes keys for. */
    private const string OWNER_ID = '42';

    /** @var array<string, string> What a statement does, by what it contains, tried in order. */
    private const array STATEMENTS = [
        'get_lock('              => 'lock',
        'release_lock('          => 'release',
        'lock_timeout'           => 'timeout',
        'pg_advisory_xact_lock(' => 'lock',
        'max('                   => 'generation',
    ];

    /** @var bool Whether a hook's work is running, so its own statements run no hook. */
    private bool $hooking = false;

    /** @var list<array{0: string, 1: string}> Each event the creation raised, as its kind and its statement. */
    private array $events = [];

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));
    }

    /**
     * Unfreeze the clock.
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
     * A unit's first key is created at generation one, live, at the clock's
     * time, with a UUID version 7 of that time as its id and 32 random bytes as
     * its data key, and stored exactly as it is returned.
     *
     * @return void
     */
    public function testAFirstKeyIsCreatedAtGenerationOne(): void
    {
        $tenant = Reference::of('App\Models\Tenant', '1');

        [$key, $dataKey] = $this->create(new KeyUnit(self::owner(), $tenant, 'billing'));

        self::assertSame(1, $key->generation);
        self::assertSame(KeyState::LIVE, $key->state);
        self::assertSame((new KeyUnit(self::owner(), $tenant, 'billing'))->digest(), $key->unit);
        self::assertSame(['App\Models\User', self::OWNER_ID], [$key->ownerType, $key->ownerId]);
        self::assertSame(['App\Models\Tenant', '1', 'billing'], [$key->tenantType, $key->tenantId, $key->category]);
        self::assertSame('2026-11-04T10:00:00.123456Z', $key->createdAt);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $key->id);
        self::assertSame(CarbonImmutable::now()->getTimestampMs(), (int) hexdec(substr(str_replace('-', '', $key->id), 0, 12)));
        self::assertSame(32, strlen($dataKey));
        self::assertEquals([$key->id => $key], $this->storedSubjectKeys());
        self::assertNull($key->erasureId);
    }

    /**
     * No key is made while the owner's latest marker records an erasure, for a
     * unit it never had a key in as for one it had: nothing is stored.
     *
     * @return void
     */
    public function testAnErasedOwnerGetsNoKey(): void
    {
        [$key] = $this->makeSubjectKey(self::owner());

        $this->eraseByHand(self::owner());

        self::assertNull($this->keyCreator()->create(self::unit()));
        self::assertNull($this->keyCreator()->create(self::unit('billing')));
        self::assertSame([$key->id], array_keys($this->storedSubjectKeys()));
        self::assertSame(KeyState::ERASED, $this->storedSubjectKeys()[$key->id]->state);

        $this->eraseByHand(Reference::of('App\Models\User', '43'));

        self::assertNull($this->keyCreator()->create(new KeyUnit(Reference::of('App\Models\User', '43'), null, 'default')));
        self::assertCount(1, $this->storedSubjectKeys());
    }

    /**
     * A reinstated owner's next key is one above the floor its erasure set,
     * whether that floor came from its own keys or was set higher, never an
     * erased generation reopened.
     *
     * @return void
     */
    public function testAReinstatedOwnerGetsAGenerationAboveItsFloor(): void
    {
        $this->makeSubjectKey(self::owner());
        $this->eraseByHand(self::owner());
        $this->reinstateByHand(self::owner());

        [$next] = $this->create(self::unit());

        self::assertSame(2, $next->generation);

        [$other] = $this->create(self::unit('billing'));

        self::assertSame(2, $other->generation);

        $fresh = Reference::of('App\Models\User', '44');

        $this->markReinstated('01932b4e-e000-7000-8000-000000000044', $fresh, 5);

        self::assertSame(6, $this->create(new KeyUnit($fresh, null, 'default'))[0]->generation);
    }

    /**
     * A unit whose live key was superseded gets the next generation, and one
     * whose largest generation is above the owner's floor goes on from it.
     *
     * @return void
     */
    public function testASupersededUnitGetsTheNextGeneration(): void
    {
        [$first] = $this->makeSubjectKey(self::owner());

        $this->supersede($first->id);

        [$second] = $this->create(self::unit());

        self::assertSame(2, $second->generation);
        self::assertNotSame($first->id, $second->id);

        $this->supersede($second->id);

        $this->markReinstated('01932b4e-e000-7000-8000-000000000001', self::owner(), 1);

        self::assertSame(3, $this->create(self::unit())[0]->generation);
    }

    /**
     * A unit with a live key is given that key and its data key, never a second
     * generation.
     *
     * @return void
     */
    public function testALiveKeyIsReturnedNotRemade(): void
    {
        [$key, $dataKey] = $this->create(self::unit());

        self::assertSame([$key->id, $dataKey], [$this->create(self::unit())[0]->id, $this->create(self::unit())[1]]);
        self::assertCount(1, $this->storedSubjectKeys());
    }

    /**
     * Two creations that race past every lock are settled by the unit's unique
     * index: the one whose insert is refused re-reads the unit's live
     * key, verified, and returns it with its data key, so one key is stored;
     * when the winner is no longer live, as after an erasure meanwhile, none is
     * returned.
     *
     * @return void
     */
    public function testACreationRaceIsSettledByTheUniqueIndexAndAReRead(): void
    {
        $winnerKey = hash('sha256', 'the winner', true);
        $winner    = $this->signedSubjectKey(self::unit(), 1, $winnerKey, '01932b4e-9000-7000-8000-00000000beef');

        $this->raceTheInsertWith($winner, false);

        [$returned, $dataKey] = $this->create(self::unit());

        self::assertSame($winner->id, $returned->id);
        self::assertSame($winnerKey, $dataKey);
        self::assertSame([$winner->id], array_keys($this->storedSubjectKeys()));

        $lost = $this->signedSubjectKey(self::unit('billing'), 1, hash('sha256', 'the lost', true), '01932b4e-9000-7000-8000-00000000feed');

        $this->raceTheInsertWith($lost, true);

        self::assertNull($this->keyCreator()->create(self::unit('billing')));
        self::assertSame(KeyState::ERASED, $this->storedSubjectKeys()[$lost->id]->state);
        self::assertCount(2, $this->storedSubjectKeys());
    }

    /**
     * A live key of the unit that another creation made while this one waited
     * for the lock is found after the lock and returned with its data key,
     * rather than a second live generation made.
     *
     * @return void
     */
    public function testALiveKeyFoundAfterTheLockIsReturnedNotDoubled(): void
    {
        $other = null;

        $this->atTheLock(function () use (&$other): void {
            $other = $this->create(self::unit());
        });

        [$key, $dataKey] = $this->create(self::unit());

        self::assertIsArray($other);
        self::assertSame($other[0]->id, $key->id);
        self::assertSame($other[1], $dataKey);
        self::assertSame([$key->id], array_keys($this->storedSubjectKeys()));
        self::assertSame(1, $key->generation);
    }

    /**
     * The owner's marker, the unit's live key and its largest generation are
     * read, and the key inserted, in one transaction, the owner's lock taken
     * before the reads: on MySQL on the session before the transaction begins
     * and released after it commits, on PostgreSQL first inside it with its
     * wait bounded, and on SQLite by the transaction itself.
     *
     * @return void
     */
    public function testTheReadsAndTheInsertAreOneTransaction(): void
    {
        $this->listen();

        $this->create(self::unit());

        $driver = $this->keyConnection()->getDriverName();
        $kinds  = array_map(fn (array $event): string => $this->kindOf($event), $this->events);

        $expected = match ($driver) {
            'mysql' => ['lock', 'begin', 'marker', 'live', 'generation', 'insert', 'commit', 'release'],
            'pgsql' => ['begin', 'timeout', 'lock', 'marker', 'live', 'generation', 'insert', 'commit'],
            default => ['begin', 'marker', 'live', 'generation', 'insert', 'commit'],
        };

        self::assertSame($expected, $kinds);
    }

    /**
     * The data key is wrapped under the wrapper's current key bound to its own
     * row: it unwraps under the row's wrap context, and under a context naming
     * another row, unit, generation or wrapping key it does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWrappedKeyIsBoundToItsRow(): void
    {
        [$key, $dataKey] = $this->create(self::unit());

        $wrapper = $this->keyWrapper();
        $stored  = $this->storedSubjectKeys()[$key->id];

        self::assertSame($wrapper->currentKeyId(), $stored->wrapKeyId);
        self::assertNotNull($stored->wrappedKey);
        self::assertSame($dataKey, $wrapper->unwrap($stored->wrappedKey, $stored->wrapKeyId, $stored->wrapContext()));

        foreach (
            [
                SubjectKeyRow::wrapContextOf('01932b4e-9000-7000-8000-00000000beef', $stored->unit, 1, $stored->wrapKeyId),
                SubjectKeyRow::wrapContextOf($stored->id, self::unit('billing')->digest(), 1, $stored->wrapKeyId),
                SubjectKeyRow::wrapContextOf($stored->id, $stored->unit, 2, $stored->wrapKeyId),
                SubjectKeyRow::wrapContextOf($stored->id, $stored->unit, 1, 'another'),
            ] as $index => $context
        ) {
            try {
                $wrapper->unwrap($stored->wrappedKey, $stored->wrapKeyId, $context);
                self::fail("The wrapped key unwrapped under context {$index}.");
            } catch (\UnexpectedValueException) {
                // The wrapped key is bound to its own row
            }
        }
    }

    /**
     * The row is signed under the integrity ring's signing key, which it names,
     * and verifies; a stored row moved to another generation does not.
     *
     * @return void
     */
    public function testTheRowIsSigned(): void
    {
        [$key] = $this->create(self::unit());

        $signer = app(SubjectKeySigner::class);
        $stored = $this->storedSubjectKeys()[$key->id];

        self::assertSame(app(KeyRing::class)->signingKey()->id, $stored->keyId);
        self::assertTrue($signer->verifies($stored));

        $moved = SubjectKeyRow::fromRow(['generation' => 2] + $stored->toRow());

        self::assertFalse($signer->verifies($moved));
    }

    /**
     * The owner's marker is read once the lock is held: an erasure that commits
     * as the creation asks for the lock, after anything the creation could have
     * read before it, is seen, and no key is made.
     *
     * @return void
     */
    public function testTheMarkerIsReadAfterTheLock(): void
    {
        $this->atTheLock(function (): void {
            $this->eraseByHand(self::owner());
        });

        self::assertNull($this->keyCreator()->create(self::unit()));
        self::assertSame([], $this->storedSubjectKeys());
        self::assertTrue(app(OwnerMarkers::class)->latest($this->keyConnection(), self::owner())?->isErasure());
    }

    /**
     * A creation that fails, here because the wrapper cannot wrap, leaves no
     * key, no transaction open and no session behind, and releases the owner's
     * lock, so the next creation for the owner is made at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionIsClosedAndTheOwnerReleasedOnFailure(): void
    {
        app()->instance(KeyWrapper::class, new class implements KeyWrapper {
            /**
             * The id of the wrapping key a new data key is wrapped under.
             *
             * @return string
             */
            #[\Override]
            public function currentKeyId(): string
            {
                return 'broken';
            }

            /**
             * Refuse to wrap.
             *
             * @param  string  $dataKey
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string
            {
                throw new \RuntimeException('The key service is unavailable.');
            }

            /**
             * Refuse to unwrap.
             *
             * @param  string  $wrapped
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string
            {
                throw new \RuntimeException('The key service is unavailable.');
            }
        });

        $this->listen();

        try {
            app(KeyCreator::class)->create(self::unit());
            self::fail('Expected the creation to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The key service is unavailable.', $exception->getMessage());
        }

        $kinds  = array_map(fn (array $event): string => $this->kindOf($event), $this->events);
        $driver = $this->keyConnection()->getDriverName();

        self::assertSame($driver === 'mysql' ? ['rollback', 'release'] : ['rollback'], array_slice($kinds, $driver === 'mysql' ? -2 : -1));
        self::assertSame([], $this->storedSubjectKeys());
        self::assertSame(0, $this->keyConnection()->transactionLevel());
        self::assertSame([], array_values(array_filter(array_keys(DB::getConnections()), static fn (string $name): bool => str_starts_with($name, KeySession::SESSION_PREFIX))));

        if ($driver === 'mysql') {
            self::assertEquals(1, ((array) $this->keyConnection()->selectOne('select is_free_lock(?) as free', [OwnerLock::name(self::owner())]))['free'] ?? null);
        }

        app()->instance(KeyWrapper::class, app(LocalKeyWrapper::class));

        self::assertSame(1, $this->create(self::unit())[0]->generation);
    }

    /**
     * A wrapped key that does not unwrap to the data key it was made from, as a
     * faulty wrapper gives, is never stored: the creation throws, so the field
     * is dropped rather than sealed under a key that could not be recovered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewKeyThatDoesNotUnwrapIsNeverStored(): void
    {
        $local = app(LocalKeyWrapper::class);

        app()->instance(KeyWrapper::class, new class ($local) implements KeyWrapper {
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

        try {
            app(KeyCreator::class)->create(self::unit());
            self::fail('Expected the creation to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A new key does not unwrap to its data key under its wrapping key, so it is not stored.', $exception->getMessage());
        }

        self::assertSame([], $this->storedSubjectKeys());
    }

    /**
     * A live key of the unit that fails its signature is refused rather than
     * returned or doubled.
     *
     * @return void
     */
    public function testALiveKeyThatFailsItsSignatureIsRefused(): void
    {
        [$key] = $this->create(self::unit());

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['hmac' => str_repeat('d', 64)]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A live subject key does not verify under its signing key.');

        $this->keyCreator()->create(self::unit());
    }

    /**
     * Each key is given a data key of its own.
     *
     * @return void
     */
    public function testEachKeyHasAFreshDataKey(): void
    {
        self::assertNotSame($this->create(self::unit())[1], $this->create(self::unit('billing'))[1]);
    }

    /**
     * The data key a creation returns seals a field that opens under the same
     * key at the same entry and path, in the configured log, and at no other
     * entry.
     *
     * @return void
     */
    public function testTheDataKeySealsAFieldThatOpensWhereItWasSealed(): void
    {
        [$key, $dataKey] = $this->create(self::unit());

        $entry    = '01932b4e-1000-7000-8000-000000000001';
        $path     = ['properties', 'card', 'last4'];
        $logId    = app(SealSettings::class)->logId();
        $envelope = $this->sealEnvelope($dataKey, $key->id, '4242', $entry, $path);

        self::assertSame(1, $envelope['v']);
        self::assertSame($key->id, $envelope['k']);
        self::assertSame('"4242"', FieldCipher::open($dataKey, $key->id, 1, $envelope['c'], $entry, $path, $logId));

        $this->expectException(\UnexpectedValueException::class);

        FieldCipher::open($dataKey, $key->id, 1, $envelope['c'], '01932b4e-1000-7000-8000-000000000002', $path, $logId);
    }

    /**
     * The owner every test makes keys for.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\User', self::OWNER_ID);
    }

    /**
     * The owner's tenantless unit of the category.
     *
     * @param  string  $category
     * @return \SineMacula\Laravel\AuditLog\Keys\KeyUnit
     */
    private static function unit(string $category = self::KEY_CATEGORY): KeyUnit
    {
        return new KeyUnit(self::owner(), null, $category);
    }

    /**
     * The unit's key and data key, which the test requires to be made.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: string}
     */
    private function create(KeyUnit $unit): array
    {
        $made = $this->keyCreator()->create($unit);

        self::assertNotNull($made, 'No key was made for the unit.');

        return $made;
    }

    /**
     * Insert a marker reinstating the owner at the floor, as a reinstatement
     * leaves one.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  int  $floor
     * @return void
     */
    private function markReinstated(string $id, Reference $owner, int $floor): void
    {
        app(OwnerMarkers::class)->insert($this->keyConnection(), new OwnerMarker($id, $owner, MarkerTransition::REINSTATED, $floor, 99, '2026-11-01T12:00:00.000000Z'));
    }

    /**
     * Mark the key superseded, as a rotation does.
     *
     * @param  string  $id
     * @return void
     */
    private function supersede(string $id): void
    {
        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $id)->update(['state' => KeyState::SUPERSEDED->value]);
    }

    /**
     * Run the work once, as the next creation is about to run its lock
     * statement, or on SQLite, which takes none, its first read inside its
     * transaction, on whichever connection the creation runs.
     *
     * @param  \Closure(): void  $work
     * @return void
     */
    private function atTheLock(\Closure $work): void
    {
        $done = false;

        $this->beforeEveryStatement(static function (Connection $connection, string $query) use (&$done, $work): void {
            $sqlite = $connection->getDriverName() === 'sqlite';
            $lock   = $sqlite
                ? $connection->transactionLevel() > 0 && str_contains($query, KeyTables::ownerErasuresTable())
                : str_contains($query, 'get_lock(') || str_contains($query, 'pg_advisory_xact_lock(');

            if ($done || !$lock) {
                return;
            }

            $done = true;

            $work();
        });
    }

    /**
     * Make the next creation's insert of the winner's unit meet the winner,
     * already stored, as a creation that raced past every lock would leave
     * it; with `$erased`, the winner is tombstoned once the creation's
     * transaction has rolled back, as an erasure meanwhile would leave it.
     *
     * On in-memory SQLite the winner is stored inside the creation's own
     * transaction, which rolls back with the refused insert, so it is stored
     * again once the rollback has run.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $winner
     * @param  bool  $erased
     * @return void
     */
    private function raceTheInsertWith(SubjectKeyRow $winner, bool $erased): void
    {
        $armed = true;

        $this->beforeEveryStatement(function (Connection $connection, string $query) use (&$armed, $winner): void {
            if (!$armed || !str_starts_with(strtolower($query), 'insert into ' . $connection->getQueryGrammar()->wrapTable(KeyTables::subjectKeysTable()))) {
                return;
            }

            $armed = false;

            $this->insertSubjectKey($winner);
        });

        Event::listen(TransactionRolledBack::class, function () use ($winner, $erased): void {
            $keys = $this->keyConnection()->table(KeyTables::subjectKeysTable());

            if (!$keys->clone()->where('id', $winner->id)->exists()) {
                $this->insertSubjectKey($winner);
            }

            if (!$erased) {
                return;
            }

            $keys->clone()->where('id', $winner->id)->update(['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => '01932b4e-e000-7000-8000-000000000001']);
        });
    }

    /**
     * Call the callback before every statement the storage connection and any
     * connection established from now on runs, guarding against its own
     * statements.
     *
     * @param  \Closure(\Illuminate\Database\Connection, string): void  $callback
     * @return void
     */
    private function beforeEveryStatement(\Closure $callback): void
    {
        $hook = function (string $query, array $bindings, Connection $connection) use ($callback): void {
            if ($this->hooking) {
                return;
            }

            $this->hooking = true;

            try {
                $callback($connection, $query);
            } finally {
                $this->hooking = false;
            }
        };

        $this->keyConnection()->beforeExecuting($hook);

        Event::listen(ConnectionEstablished::class, static function (ConnectionEstablished $event) use ($hook): void {
            $event->connection->beforeExecuting($hook);
        });
    }

    /**
     * Record the transactions and statements every connection runs from now on.
     *
     * @return void
     */
    private function listen(): void
    {
        Event::listen(TransactionBeginning::class, function (): void {
            $this->events[] = ['begin', ''];
        });

        Event::listen(TransactionCommitted::class, function (): void {
            $this->events[] = ['commit', ''];
        });

        Event::listen(TransactionRolledBack::class, function (): void {
            $this->events[] = ['rollback', ''];
        });

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->events[] = ['statement', strtolower($query->sql)];
        });
    }

    /**
     * What an event was: a transaction's begin, commit or rollback, or the
     * statement it ran, named by what it does.
     *
     * @param  array{0: string, 1: string}  $event
     * @return string
     */
    private function kindOf(array $event): string
    {
        [$kind, $sql] = $event;

        if ($kind !== 'statement') {
            return $kind;
        }

        foreach (self::STATEMENTS as $contains => $what) {
            if (str_contains($sql, $contains)) {
                return $what;
            }
        }

        return match (true) {
            str_contains($sql, KeyTables::ownerErasuresTable()) => 'marker',
            str_starts_with($sql, 'insert')                     => 'insert',
            str_contains($sql, KeyTables::subjectKeysTable())   => 'live',
            default                                             => $sql,
        };
    }
}
