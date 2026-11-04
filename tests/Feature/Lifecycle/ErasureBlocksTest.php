<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlock;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlocks;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Feature tests for which of an owner's keys an erasure must keep, on whichever
 * engine the suite runs against: a key is blocked by each hold that matches an
 * entry it encrypted, by preservation decided per entry from its occurrence,
 * and as `unverified` by an entry that fails its HMAC, edited or signed under a
 * key the ring does not hold; a key use whose entry was pruned blocks and
 * counts nothing; the entries are read in pages of 1,000 led by the key and
 * seeking on the entry; and the entries of every key nothing blocks are summed.
 *
 * Keys are made through the key creator and entries stored through the database
 * store, which writes each envelope's key use, so the eraser is not relied on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureBlocks::class)]
final class ErasureBlocksTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var string When every decision is made: the erasure's day. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var string The category of every seeded entry, and of the keys made for it. */
    private const string CATEGORY = 'finance';

    /** @var string The hold every test that holds places. */
    private const string HOLD_ID = '01932b4e-9000-7000-8000-0000000000b1';

    /** @var string Another hold. */
    private const string OTHER_HOLD_ID = '01932b4e-9000-7000-8000-0000000000b2';

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
     * A hold that matches one entry of a key blocks that key, naming the hold,
     * and leaves a key whose entries it does not match unblocked; a second hold
     * matching the same key is named too.
     *
     * @return void
     */
    public function testAHoldMatchingOneEntryBlocksItsKey(): void
    {
        [$held]  = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);
        [$other] = $this->makeSubjectKey(self::owner(), Reference::of('organisation', 'org_02'), self::CATEGORY);

        $this->seedEncrypted($held);
        $this->seedEncrypted($held, ['tenant_id' => 'org_99']);
        $this->seedEncrypted($other, ['tenant_id' => 'org_02']);

        $holds = [
            self::hold(self::HOLD_ID, HoldScope::tenants(self::tenant())),
            self::hold(self::OTHER_HOLD_ID, HoldScope::all()->categories(self::CATEGORY)->about(Reference::of('invoice', 'inv_0042'))),
        ];

        [$blocks, $affected] = $this->blocksOf([$held, $other], $holds);

        self::assertCount(2, $blocks);
        self::assertSame([$held->id, $held->unit, $held->generation], [$blocks[0]->keyId, $blocks[0]->unit, $blocks[0]->generation]);
        self::assertSame(['held:' . self::HOLD_ID, 'held:' . self::OTHER_HOLD_ID], $blocks[0]->reasons);
        self::assertSame($other->id, $blocks[1]->keyId);
        self::assertSame(['held:' . self::OTHER_HOLD_ID], $blocks[1]->reasons);
        self::assertSame(0, $affected);
    }

    /**
     * A key nothing holds is not blocked, and its entries are counted.
     *
     * @return void
     */
    public function testAKeyNothingHoldsIsNotBlocked(): void
    {
        [$key] = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);

        $this->seedEncrypted($key);
        $this->seedEncrypted($key);

        [$blocks, $affected] = $this->blocksOf([$key], [self::hold(self::HOLD_ID, HoldScope::tenants(Reference::of('organisation', 'org_02')))]);

        self::assertSame([], $blocks);
        self::assertSame(2, $affected);
    }

    /**
     * Preservation is decided per entry from its occurrence: an entry that
     * occurred at or after the erasure's midnight less the days preserved
     * blocks its key, `preserved:<category>`, and one that occurred before that
     * does not.
     *
     * @return void
     */
    public function testPreservationIsDecidedPerEntryFromItsOccurrence(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.preserve', [self::CATEGORY => 30]);

        [$old]    = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);
        [$recent] = $this->makeSubjectKey(Reference::of('user', '43'), self::tenant(), self::CATEGORY);

        // The erasure's midnight is 2026-11-04, so the cut-off is 2026-10-05
        $this->seedEncrypted($old, [], '2026-10-04T23:59:59.999999Z');
        $this->seedEncrypted($recent, [], '2026-10-04T23:59:59.999999Z');
        $this->seedEncrypted($recent, [], '2026-10-05T00:00:00.000000Z');

        [$blocks, $affected] = $this->blocksOf([$old, $recent], []);

        self::assertCount(1, $blocks);
        self::assertSame($recent->id, $blocks[0]->keyId);
        self::assertSame(['preserved:' . self::CATEGORY], $blocks[0]->reasons);
        self::assertSame(1, $affected);
    }

    /**
     * A category preserved forever blocks every entry, however old.
     *
     * @return void
     */
    public function testAForeverPreservationBlocksEveryEntry(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.preserve', [self::CATEGORY => 0]);

        [$key] = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);

        $this->seedEncrypted($key, [], '2001-01-01T00:00:00.000000Z');

        [$blocks] = $this->blocksOf([$key], []);

        self::assertSame(['preserved:' . self::CATEGORY], $blocks[0]->reasons);
    }

    /**
     * Preservation is the key's own category and tenant's: another category's
     * preservation blocks nothing.
     *
     * @return void
     */
    public function testAnotherCategorysPreservationBlocksNothing(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.preserve', ['billing' => 0]);

        [$key] = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);

        $this->seedEncrypted($key);

        self::assertSame([], $this->blocksOf([$key], [])[0]);
    }

    /**
     * A policy that keeps a category for less than it preserves it refuses the
     * erasure, as it refuses a prune.
     *
     * @return void
     */
    public function testAConflictingPolicyRefuses(): void
    {
        $policy = new class implements RetentionPolicy {
            /**
             * The policy's version.
             *
             * @return string
             */
            #[\Override]
            public function version(): string
            {
                return 'conflicting';
            }

            /**
             * Ten days for every category.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return int
             */
            #[\Override]
            public function retainFor(string $category, ?Reference $tenant): int
            {
                return 10;
            }

            /**
             * Thirty days for every category: longer than it is kept.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return int
             */
            #[\Override]
            public function preserveFor(string $category, ?Reference $tenant): int
            {
                return 30;
            }
        };

        [$key] = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);

        $this->expectException(RetentionConflictException::class);

        app(ErasureBlocks::class)->for($this->connection(), [$key], [], new RetentionDecisions($policy, CarbonImmutable::now()));
    }

    /**
     * A key use whose entry was pruned blocks nothing and counts nothing, even
     * under a hold of every entry.
     *
     * @return void
     */
    public function testAPrunedEntrysKeyUseBlocksNothing(): void
    {
        [$key] = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);

        $pruned = $this->seedEncrypted($key);

        $this->seedEncrypted($key);
        $this->connection()->table(EntrySettings::table())->where('id', $pruned)->delete();

        [$blocks, $affected] = $this->blocksOf([$key], []);

        self::assertSame([], $blocks);
        self::assertSame(1, $affected);
        self::assertSame(2, $this->connection()->table(KeyTables::keyUsesTable())->where('key_id', $key->id)->count());

        $this->connection()->table(EntrySettings::table())->delete();

        self::assertSame([[], 0], $this->blocksOf([$key], [self::hold(self::HOLD_ID, HoldScope::all())]));
    }

    /**
     * The entries are read in pages of 1,000 key uses, led by the key's id and
     * seeking on the entry's id, so a held entry after the first page is still
     * found, another key's key uses are never read, and a key with fewer key
     * uses than a page is read in one statement.
     *
     * @return void
     */
    public function testTheEntriesArePagedByKeyAndEntry(): void
    {
        [$key]   = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);
        [$other] = $this->makeSubjectKey(Reference::of('user', '43'), self::tenant(), self::CATEGORY);

        $this->insertKeyUses($key->id, ErasureBlocks::PAGE, '01900000');
        $this->insertKeyUses($other->id, 5, '01900000');

        $this->seedEncrypted($key);
        $this->seedEncrypted($other);

        $pages = $this->keyUsePages();

        [$blocks, $affected] = $this->blocksOf([$key, $other], [self::hold(self::HOLD_ID, HoldScope::all()->about(Reference::of('nobody', 'none')))]);

        self::assertSame([], $blocks);
        self::assertSame(2, $affected);
        self::assertSame([[$key->id], [$key->id, '01900000-0000-7000-8000-000000001000'], [$other->id]], $pages->getArrayCopy());

        $pages->exchangeArray([]);

        [$blocks] = $this->blocksOf([$key], [self::hold(self::HOLD_ID, HoldScope::all())]);

        self::assertSame($key->id, $blocks[0]->keyId);
        self::assertCount(2, $pages);
    }

    /**
     * Rows of `[the columns an entry is edited to]`: an entry that fails its
     * HMAC, edited or signed under a key the ring does not hold, or of an
     * integrity version the signer does not support.
     *
     * @return iterable<string, array{0: array<string, int|string>}>
     */
    public static function provideUnauthenticEntries(): iterable
    {
        yield from [
            'an edited reason'       => [['reason' => 'edited']],
            'a forged hmac'          => [['hmac' => str_repeat('0', 64)]],
            'an unknown signing key' => [['key_id' => 'retired-key']],
            'an unsupported version' => [['integrity_version' => 99]],
        ];
    }

    /**
     * An entry that does not authenticate blocks the key that encrypted it,
     * `unverified`, and nothing else it says is believed: not even a hold that
     * would match it.
     *
     * @param  array<string, int|string>  $columns
     * @return void
     */
    #[DataProvider('provideUnauthenticEntries')]
    public function testAnEntryFailingItsHmacBlocksItsKey(array $columns): void
    {
        [$key]   = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);
        [$clean] = $this->makeSubjectKey(Reference::of('user', '43'), self::tenant(), self::CATEGORY);

        $edited = $this->seedEncrypted($key);

        $this->seedEncrypted($key);
        $this->seedEncrypted($clean);
        $this->connection()->table(EntrySettings::table())->where('id', $edited)->update($columns);

        [$blocks, $affected] = $this->blocksOf([$key, $clean], [self::hold(self::HOLD_ID, HoldScope::tenants(Reference::of('organisation', 'org_02')))]);

        self::assertCount(1, $blocks);
        self::assertSame($key->id, $blocks[0]->keyId);
        self::assertSame(['unverified'], $blocks[0]->reasons);
        self::assertSame(1, $affected);
    }

    /**
     * An entry edited so a hold no longer matches it still blocks its key: the
     * edit fails its HMAC, so it is `unverified`, never released.
     *
     * @return void
     */
    public function testAnEntryEditedToLeaveAHoldBlocksItsKey(): void
    {
        [$key] = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);

        $id    = $this->seedEncrypted($key);
        $holds = [self::hold(self::HOLD_ID, HoldScope::tenants(self::tenant()))];

        self::assertSame(['held:' . self::HOLD_ID], $this->blocksOf([$key], $holds)[0][0]->reasons);

        $this->connection()->table(EntrySettings::table())->where('id', $id)->update(['tenant_id' => 'org_02']);

        self::assertSame([ErasureBlock::UNVERIFIED], $this->blocksOf([$key], $holds)[0][0]->reasons);
    }

    /**
     * The entries affected are summed over the keys nothing blocks, each key's
     * present entries once; a blocked key's entries are not counted.
     *
     * @return void
     */
    public function testTheEntriesAffectedAreSummedPerKey(): void
    {
        [$first]   = $this->makeSubjectKey(self::owner(), self::tenant(), self::CATEGORY);
        [$second]  = $this->makeSubjectKey(self::owner(), self::tenant(), 'billing');
        [$blocked] = $this->makeSubjectKey(self::owner(), Reference::of('organisation', 'org_02'), self::CATEGORY);

        $this->seedEncrypted($first);
        $this->seedEncrypted($first);
        $this->seedEncrypted($second, ['category' => 'billing']);
        $this->seedEncrypted($blocked, ['tenant_id' => 'org_02']);
        $this->seedEncrypted($blocked, ['tenant_id' => 'org_02']);

        [$blocks, $affected] = $this->blocksOf([$first, $second, $blocked], [self::hold(self::HOLD_ID, HoldScope::tenants(Reference::of('organisation', 'org_02')))]);

        self::assertSame([$blocked->id], array_map(static fn (ErasureBlock $block): string => $block->keyId, $blocks));
        self::assertSame(3, $affected);
        self::assertSame([[], 0], $this->blocksOf([], []));
    }

    /**
     * Store an entry holding a card under the key, with the fields given in
     * place of its own, occurring at the instant given or the factory's, and
     * return its id. The database store writes its key use.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  array<string, string>  $fields
     * @param  ?string  $occurredAt
     * @return string
     */
    private function seedEncrypted(SubjectKeyRow $key, array $fields = [], ?string $occurredAt = null): string
    {
        $id       = Str::uuid7()->toString();
        $envelope = ['v' => 1, 'k' => $key->id, 'c' => 'Y2lwaGVydGV4dC1vZi10aGUtY2FyZA'];

        return $this->seedEntry(['properties' => ['card' => $envelope], ...$fields], $occurredAt, $id);
    }

    /**
     * Insert key uses of the key for entries that are not stored, their ids
     * starting with the prefix and numbered from 1.
     *
     * @param  string  $keyId
     * @param  int  $count
     * @param  string  $prefix
     * @return void
     */
    private function insertKeyUses(string $keyId, int $count, string $prefix): void
    {
        $rows = array_map(static fn (int $index): array => ['key_id' => $keyId, 'entry_id' => sprintf('%s-0000-7000-8000-%012d', $prefix, $index)], range(1, $count));

        foreach (array_chunk($rows, 200) as $chunk) {
            $this->connection()->table(KeyTables::keyUsesTable())->insert($chunk);
        }
    }

    /**
     * Record the bindings of every read of the key uses from now.
     *
     * @return \ArrayObject<int, list<scalar|null>>
     */
    private function keyUsePages(): \ArrayObject
    {
        /** @var \ArrayObject<int, list<scalar|null>> $pages */
        $pages   = new \ArrayObject;
        $pattern = '/from [`"]?' . preg_quote(KeyTables::keyUsesTable(), '/') . '[`"]? /';

        DB::listen(static function (QueryExecuted $query) use ($pages, $pattern): void {
            if (preg_match($pattern, $query->sql) !== 1 || !str_starts_with($query->sql, 'select')) {
                return;
            }

            /** @var list<scalar|null> $bindings */
            $bindings = array_values($query->bindings);

            $pages->append($bindings);
        });

        return $pages;
    }

    /**
     * The blocks of the keys under the holds, decided now by the configured
     * policy on the storage connection.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keys
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlock>, 1: int}
     */
    private function blocksOf(array $keys, array $holds): array
    {
        $decisions = new RetentionDecisions(app(ConfiguredRetentionPolicy::class), CarbonImmutable::now());

        return app(ErasureBlocks::class)->for($this->connection(), $keys, $holds, $decisions);
    }

    /**
     * The storage connection, where the keys, the key uses and the entries
     * live.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * An active hold of the id over the scope, placed now.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private static function hold(string $id, HoldScope $scope): Hold
    {
        return new Hold($id, $scope, HoldBasis::LEGAL_CLAIM, null, '2026-11-04T09:00:00.000000Z', Reference::of('user', '7'), 'case.review', null, $id, 1);
    }

    /**
     * The owner every seeded entry's actor is.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('user', '42');
    }

    /**
     * The tenant every seeded entry is for, unless a test gives another.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function tenant(): Reference
    {
        return Reference::of('organisation', 'org_01');
    }
}
