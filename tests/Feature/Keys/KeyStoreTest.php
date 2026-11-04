<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for where the owners' keys are read: every live unit of a
 * record in one statement, each verified, a key that fails its signature or
 * names an unknown signing key refused; keys and erasure rows by id in one
 * statement each, through the writer and unverified, ids of another form and
 * rows too malformed to read left out; an owner's keys in every unit and
 * state; a unit's live key and largest generation; and a page of every key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyStore::class)]
final class KeyStoreTest extends TestCase
{
    use InteractsWithReadWriteSplit, MakesSubjectKeys;

    /** @var list<string> The migrations a split's two databases are given, beside the entries. */
    private const array SPLIT_MIGRATIONS = [
        '2026_11_02_000700_create_audit_log_lifecycle_table.php',
        '2026_11_02_001100_create_audit_log_subject_keys_table.php',
        '2026_11_02_001200_create_audit_log_owner_erasures_table.php',
        '2026_11_02_001300_create_audit_log_key_uses_table.php',
    ];

    /** @var string An id no key or journal row has. */
    private const string UNKNOWN_ID = '01932b4e-0000-7000-8000-00000000dead';

    /** @var list<string> The statements run since the test began listening. */
    private array $statements = [];

    /**
     * Close the split's connections and delete their files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeReadWriteSplit();

        parent::tearDown();
    }

    /**
     * The live key of every unit of a record that has one is read in one
     * statement, keyed by the unit's digest, each unit asked for once however
     * often it is given; a unit with no key is absent, and no unit at all asks
     * nothing.
     *
     * @return void
     */
    public function testLiveKeysForEveryUnitInOneStatement(): void
    {
        $user   = Reference::of('App\Models\User', '42');
        $team   = Reference::of('App\Models\Team', '7');
        $tenant = Reference::of('App\Models\Tenant', '1');

        $units = [new KeyUnit($user, null, 'default'), new KeyUnit($user, $tenant, 'billing'), new KeyUnit($team, null, 'default')];

        $made = array_map(fn (KeyUnit $unit): SubjectKeyRow => $this->makeSubjectKey($unit->owner, $unit->tenant, $unit->category)[0], $units);
        $none = new KeyUnit(Reference::of('App\Models\User', '43'), null, 'default');

        $this->listen();

        $live = self::store()->liveFor([...$units, $none, $units[0]]);

        $expected = array_combine(array_map(static fn (KeyUnit $unit): string => $unit->digest(), $units), array_map(static fn (SubjectKeyRow $row): string => $row->id, $made));
        $found    = array_map(static fn (SubjectKeyRow $row): string => $row->id, $live);

        ksort($expected);
        ksort($found);

        self::assertCount(1, $this->statements);
        self::assertSame($expected, $found);

        $this->statements = [];

        self::assertSame([], self::store()->liveFor([]));
        self::assertSame([], $this->statements);
    }

    /**
     * Only live keys are found: a superseded unit's live generation is, a unit
     * whose one key is superseded has none, and an erased owner's units have
     * none.
     *
     * @return void
     */
    public function testOnlyLiveKeysAreFound(): void
    {
        $user   = Reference::of('App\Models\User', '42');
        $erased = Reference::of('App\Models\User', '43');

        $rotated    = new KeyUnit($user, null, 'default');
        $superseded = new KeyUnit($user, null, 'billing');
        $gone       = new KeyUnit($erased, null, 'default');

        [$first] = $this->makeSubjectKey($user);

        $this->supersede($first->id);

        [$second] = $this->makeSubjectKey($user);
        [$lone]   = $this->makeSubjectKey($user, null, 'billing');

        $this->supersede($lone->id);
        $this->makeSubjectKey($erased);
        $this->eraseByHand($erased);

        $live = self::store()->liveFor([$rotated, $superseded, $gone]);

        self::assertSame([$rotated->digest()], array_keys($live));
        self::assertSame($second->id, $live[$rotated->digest()]->id);
        self::assertSame(2, $live[$rotated->digest()]->generation);
        self::assertSame(KeyState::LIVE, $live[$rotated->digest()]->state);
        self::assertSame($second->id, self::store()->liveOf($this->keyConnection(), $rotated)?->id);
        self::assertNull(self::store()->liveOf($this->keyConnection(), $superseded));
        self::assertNull(self::store()->liveOf($this->keyConnection(), $gone));
    }

    /**
     * A live key that fails its signature, or names a signing key the ring does
     * not hold, is refused whenever it is read to encrypt with, naming neither
     * the key nor its owner.
     *
     * @return void
     */
    public function testARowThatFailsItsSignatureIsRefused(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $unit  = new KeyUnit($owner, null, 'default');

        [$key] = $this->makeSubjectKey($owner);

        foreach ([['hmac' => str_repeat('a', 64)], ['key_id' => 'retired'], ['created_at' => '2020-01-01 00:00:00.000000']] as $tampered) {
            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($tampered);

            foreach ([static fn (): array => self::store()->liveFor([$unit]), fn (): ?SubjectKeyRow => self::store()->liveOf($this->keyConnection(), $unit)] as $read) {
                try {
                    $read();
                    self::fail('Expected the key to be refused.');
                } catch (\UnexpectedValueException $exception) {
                    self::assertSame('A live subject key does not verify under its signing key.', $exception->getMessage());
                    self::assertStringNotContainsString($key->id, $exception->getMessage());
                }
            }

            $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update($key->toRow());
        }

        self::assertSame($key->id, self::store()->liveFor([$unit])[$unit->digest()]->id);
    }

    /**
     * Keys are read by id in one statement through the storage connection's
     * writer, never a replica, in any state and unverified, keyed by id: an id
     * no key has, an id that is no canonical UUID and a row too malformed to
     * read are left out, and no id at all asks nothing.
     *
     * @return void
     */
    public function testByIdsReadsTheWriter(): void
    {
        $this->useKeysOnASplit();

        $owner = Reference::of('App\Models\User', '42');

        [$live]     = $this->makeSubjectKey($owner);
        [$tampered] = $this->makeSubjectKey($owner, null, 'billing');
        [$broken]   = $this->makeSubjectKey($owner, null, 'support');
        [$erased]   = $this->makeSubjectKey(Reference::of('App\Models\User', '43'));

        $this->eraseByHand(Reference::of('App\Models\User', '43'));

        $keys = DB::connection(self::PRIMARY_CONNECTION)->table(KeyTables::subjectKeysTable());

        $keys->clone()->where('id', $tampered->id)->update(['hmac' => str_repeat('b', 64)]);
        $keys->clone()->where('id', $broken->id)->update(['unit' => str_repeat('c', 64)]);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(KeyTables::subjectKeysTable())->count());

        $this->listen();

        $read = self::store()->byIds([$live->id, $tampered->id, $broken->id, $erased->id, self::UNKNOWN_ID, strtoupper($live->id), 'key-1', $live->id]);

        self::assertCount(1, $this->statements);
        self::assertEqualsCanonicalizing([$live->id, $tampered->id, $erased->id], array_keys($read));
        self::assertSame(KeyState::ERASED, $read[$erased->id]->state);
        self::assertNull($read[$erased->id]->wrappedKey);
        self::assertSame(str_repeat('b', 64), $read[$tampered->id]->hmac);

        $this->statements = [];

        self::assertSame([], self::store()->byIds([]));
        self::assertSame([], self::store()->byIds(['not-a-uuid']));
        self::assertSame([], $this->statements);
    }

    /**
     * An owner's keys are every key of it, in every unit and state, by id, and
     * never another owner's, of another id or of another type with the same id.
     *
     * @return void
     */
    public function testOfOwnerReadsEveryUnitAndState(): void
    {
        $owner  = Reference::of('App\Models\User', '42');
        $tenant = Reference::of('App\Models\Tenant', '1');

        [$first] = $this->makeSubjectKey($owner);

        $this->supersede($first->id);

        [$second] = $this->makeSubjectKey($owner);
        [$billed] = $this->makeSubjectKey($owner, $tenant, 'billing');

        $this->makeSubjectKey(Reference::of('App\Models\User', '43'));
        $this->makeSubjectKey(Reference::of('App\Models\Team', '42'));

        $this->eraseByHand($owner, [$billed->id => ['held:case']]);

        $keys = self::store()->ofOwner($this->keyConnection(), $owner);
        $ids  = [$first->id, $second->id, $billed->id];

        sort($ids);

        self::assertSame($ids, array_map(static fn (SubjectKeyRow $key): string => $key->id, $keys));
        self::assertSame(
            [$first->id => KeyState::ERASED, $second->id => KeyState::ERASED, $billed->id => KeyState::LIVE],
            array_combine(array_map(static fn (SubjectKeyRow $key): string => $key->id, $keys), array_map(static fn (SubjectKeyRow $key): KeyState => $key->state, $keys)),
        );
        self::assertSame([], self::store()->ofOwner($this->keyConnection(), Reference::of('App\Models\User', '44')));
    }

    /**
     * An erased key's erasure rows are read by id in one statement through the
     * storage connection's writer, with their payloads and unverified, keyed by
     * id: an id no row has, an id that is no canonical UUID and a row too
     * malformed to read are left out, and no id at all asks nothing.
     *
     * @return void
     */
    public function testErasureRowsAreReadByIdOnTheWriter(): void
    {
        $this->useKeysOnASplit();

        $owner = Reference::of('App\Models\User', '42');

        [$key] = $this->makeSubjectKey($owner);

        $erasure = $this->eraseByHand($owner);
        $hold    = $this->journalHold('01932b4e-a000-7000-8000-000000000001');
        $broken  = $this->journalHold('01932b4e-a000-7000-8000-000000000002');

        DB::connection(self::PRIMARY_CONNECTION)->table(LifecycleTables::journalTable())->where('id', $broken->id)->update(['kind' => 'forgotten']);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(LifecycleTables::journalTable())->count());

        $this->listen();

        $rows = self::store()->erasureRows([$erasure->id, $hold->id, $broken->id, self::UNKNOWN_ID, 'erasure-1', $erasure->id]);

        self::assertCount(1, $this->statements);
        self::assertEqualsCanonicalizing([$erasure->id, $hold->id], array_keys($rows));
        self::assertSame(JournalKind::ERASURE, $rows[$erasure->id]->kind);
        self::assertSame($erasure->hmac, $rows[$erasure->id]->hmac);
        self::assertSame([$key->id], array_column((array) ($rows[$erasure->id]->payloadMap()['destroyed'] ?? []), 'key_id'));

        $this->statements = [];

        self::assertSame([], self::store()->erasureRows([]));
        self::assertSame([], self::store()->erasureRows(['not-a-uuid']));
        self::assertSame([], $this->statements);
    }

    /**
     * A unit's largest generation counts every state, a superseded and an
     * erased key's included, and is 0 for a unit with no key.
     *
     * @return void
     */
    public function testTheLargestGenerationCountsEveryState(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $unit  = new KeyUnit($owner, null, 'default');

        self::assertSame(0, self::store()->largestGeneration($this->keyConnection(), $unit->digest()));

        [$first] = $this->makeSubjectKey($owner);

        $this->supersede($first->id);
        $this->makeSubjectKey($owner);

        self::assertSame(2, self::store()->largestGeneration($this->keyConnection(), $unit->digest()));

        $this->eraseByHand($owner);

        self::assertSame(2, self::store()->largestGeneration($this->keyConnection(), $unit->digest()));
        self::assertSame(0, self::store()->largestGeneration($this->keyConnection(), (new KeyUnit($owner, null, 'billing'))->digest()));
    }

    /**
     * A page of every key walks them in id order from the first or after an id,
     * each as its stored row, up to the limit; a limit below one is refused.
     *
     * @return void
     */
    public function testAPageWalksEveryKeyById(): void
    {
        $ids = [];

        foreach (['41', '42', '43'] as $id) {
            $ids[] = $this->makeSubjectKey(Reference::of('App\Models\User', $id))[0]->id;
        }

        sort($ids);

        $first = self::store()->page($this->keyConnection(), null, 2);

        self::assertSame(array_slice($ids, 0, 2), array_column($first, 'id'));
        self::assertSame($this->storedSubjectKeys()[$ids[0]]->toRow()['hmac'], $first[0]['hmac']);
        self::assertSame([$ids[2]], array_column(self::store()->page($this->keyConnection(), $ids[1], 2), 'id'));
        self::assertSame([], self::store()->page($this->keyConnection(), $ids[2], 2));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A page of keys holds at least one key.');

        self::store()->page($this->keyConnection(), null, 0);
    }

    /**
     * The key store the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Keys\KeyStore
     */
    private static function store(): KeyStore
    {
        return app(KeyStore::class);
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
     * Put the storage connection on a read/write split of two SQLite files,
     * each given the journal and the key tables, so a key made through the
     * split lands on the primary alone.
     *
     * @return void
     */
    private function useKeysOnASplit(): void
    {
        $this->useReadWriteSplit();

        $config = app(ConfigRepository::class);

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);

            foreach (self::SPLIT_MIGRATIONS as $file) {
                $migration = require dirname(__DIR__, 3) . '/database/migrations/' . $file;

                self::assertIsObject($migration);
                self::assertTrue(method_exists($migration, 'up'));

                $migration->up();
            }
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);

        self::assertSame(self::SPLIT_CONNECTION, StorageConnection::name());
    }

    /**
     * Record every statement any connection runs from now on.
     *
     * @return void
     */
    private function listen(): void
    {
        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
    }
}
