<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Integration tests for the trail holding an owner's data, on whichever engine
 * the suite runs against: the entries holding a fragment sealed under any of
 * the owner's keys, in any of its tenants and categories, are found by a page,
 * a count and an export, through the key uses the store wrote with each entry
 * and the keys the key creator made; another owner's entries are not, an owner
 * whose id differs only in case included, since every engine compares the ids
 * byte for byte; and an entry holding two owners' fragments is found for each.
 *
 * Every key is made and every entry stored as the package makes and stores
 * them, so the `exists` runs over the engine's own key types: native `uuid`
 * columns on PostgreSQL, binary strings on MySQL and text on SQLite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditTrail::class)]
#[CoversClass(ScopeCompiler::class)]
final class HoldingDataOfEnginesTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var string The type of every owner. */
    private const string OWNER_TYPE = 'App\Models\User';

    /** @var string The directory the export is written to, made for each test alone. */
    private string $directory = '';

    /**
     * Bind the read path and the package's key wrapper, let every viewer see
     * every entry, and make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();
        $this->bindReading();
        $this->allowEverything();

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-holding-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the directory and what was exported into it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        array_map(unlink(...), array_filter(glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [], is_file(...)));

        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }

        parent::tearDown();
    }

    /**
     * The entries holding the owner's fragments, under its keys of two tenants
     * and two categories, and one entry of no tenant, are found by a page, a
     * count and an export, each once, however many of the owner's fragments it
     * holds.
     *
     * @return void
     */
    public function testItFindsTheOwnersEntriesOnEachEngine(): void
    {
        $owner = Reference::of(self::OWNER_TYPE, 'abc');

        $ids = [
            $this->seedHolding([$owner], tenant: 'org_01'),
            $this->seedHolding([$owner], tenant: 'org_02'),
            $this->seedHolding([$owner], tenant: 'org_01', category: 'hr'),
            $this->seedHolding([$owner, $owner], tenant: null),
        ];

        $this->seedEntry();

        $trail = app(AuditTrail::class)->visibleTo($this->viewer())->holdingDataOf($owner);

        self::assertSame(self::sorted($ids), self::sorted(self::idsOf($trail->cursorPaginate())));
        self::assertSame(4, $trail->count());
        self::assertSame(self::sorted($ids), $this->exported($trail));
    }

    /**
     * Another owner's entries are not found: neither an owner of another type,
     * nor one whose id differs only in case, nor one with no key at all.
     *
     * @return void
     */
    public function testAnotherOwnersEntriesAreNotFound(): void
    {
        $owner = Reference::of(self::OWNER_TYPE, 'abc');
        $mine  = $this->seedHolding([$owner]);

        $this->seedHolding([Reference::of(self::OWNER_TYPE, 'ABC')]);
        $this->seedHolding([Reference::of('App\Models\Customer', 'abc')]);
        $this->seedHolding([Reference::of(self::OWNER_TYPE, 'abd')]);

        $trail = app(AuditTrail::class)->visibleTo($this->viewer());

        self::assertSame([$mine], self::idsOf($trail->holdingDataOf($owner)->cursorPaginate()));
        self::assertSame(1, $trail->holdingDataOf($owner)->count());
        self::assertSame([], self::idsOf($trail->holdingDataOf(Reference::of(self::OWNER_TYPE, 'nobody'))->cursorPaginate()));
        self::assertSame(0, $trail->holdingDataOf(Reference::of(self::OWNER_TYPE, 'Abc'))->count());
    }

    /**
     * An entry holding the fragments of two owners is found for each of them,
     * beside the entries holding only that owner's, and is exported for each.
     *
     * @return void
     */
    public function testAnEntryHoldingTwoOwnersIsFoundForEach(): void
    {
        $first  = Reference::of(self::OWNER_TYPE, '42');
        $second = Reference::of(self::OWNER_TYPE, '43');
        $both   = $this->seedHolding([$first, $second]);
        $only   = $this->seedHolding([$first]);
        $other  = $this->seedHolding([$second]);
        $trail  = app(AuditTrail::class)->visibleTo($this->viewer());

        self::assertSame(self::sorted([$both, $only]), self::sorted(self::idsOf($trail->holdingDataOf($first)->cursorPaginate())));
        self::assertSame(self::sorted([$both, $other]), self::sorted(self::idsOf($trail->holdingDataOf($second)->cursorPaginate())));
        self::assertSame(self::sorted([$both, $other]), $this->exported($trail->holdingDataOf($second)));
        self::assertSame(3, $trail->inCategory('finance')->count());
    }

    /**
     * Store an entry holding a fragment of each owner, each sealed under the
     * key of the owner's unit in the entry's tenant and category, in a field of
     * its own, and return its id.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     * @param  ?string  $tenant
     * @param  string  $category
     * @return string
     */
    private function seedHolding(array $owners, ?string $tenant = 'org_01', string $category = 'finance'): string
    {
        $id         = Str::uuid7()->toString();
        $reference  = $tenant === null ? null : Reference::of('organisation', $tenant);
        $properties = [];

        foreach ($owners as $index => $owner) {
            [$key, $dataKey] = $this->makeSubjectKey($owner, $reference, $category);

            $properties['field_' . $index] = $this->sealEnvelope($dataKey, $key->id, 'fragment ' . $index, $id, ['properties', 'field_' . $index]);
        }

        $fields = ['properties' => $properties, 'category' => $category, 'tenant_type' => $reference?->type, 'tenant_id' => $reference?->id];

        return $this->seedEntry($fields, id: $id);
    }

    /**
     * Export the trail as NDJSON and return the ids of the entries the export
     * holds, sorted.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @return list<string>
     *
     * @throws \JsonException
     */
    private function exported(AuditTrail $trail): array
    {
        $path = $this->directory . '/' . Str::uuid7()->toString() . '.ndjson';

        $trail->export($path);

        $ids = [];

        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);
            self::assertIsString($decoded['id'] ?? null);

            $ids[] = $decoded['id'];
        }

        return self::sorted($ids);
    }

    /**
     * The ids of the entries the page shows, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailPage  $page
     * @return list<string>
     */
    private static function idsOf(TrailPage $page): array
    {
        return array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries);
    }

    /**
     * The ids, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        sort($ids, SORT_STRING);

        return $ids;
    }
}
