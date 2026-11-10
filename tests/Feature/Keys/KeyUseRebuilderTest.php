<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Keys\KeyUseRebuilder;
use SineMacula\Laravel\AuditLog\Lifecycle\KeyUseRebuildResult;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for rebuilding the key uses from the entries, on whichever
 * engine the suite runs against: a key use a verified entry names and the table
 * lacks is added, every envelope found at any depth; an entry whose signature
 * does not match, or whose signing key the ring does not hold, adds nothing;
 * nothing is ever removed; the entries are read in pages by id; and a dry run
 * counts without writing.
 *
 * The entries are signed as the store signs them and inserted as it inserts
 * them, without their key uses, so what is missing is the rebuild's to add.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyUseRebuilder::class)]
final class KeyUseRebuilderTest extends TestCase
{
    use InteractsWithAuditStore;

    /**
     * Every key a verified entry's envelopes name, in its properties at any
     * depth, its context and its IP address, is added once per entry; a key use
     * already stored is not added again, and a key that is not a canonical UUID
     * has none.
     *
     * @return void
     */
    public function testAMissingKeyUseIsAdded(): void
    {
        [$card, $item, $kept] = [self::keyId(), self::keyId(), self::keyId()];

        $first  = $this->storeEntry(['card' => self::envelope($card), 'items' => [self::envelope($item), self::envelope($card)], 'other' => self::envelope('not-a-uuid')]);
        $second = $this->storeEntry(['card' => self::envelope($kept), 'note' => self::envelope($card)]);

        $this->insertUses([[$kept, $second]]);

        $result = $this->rebuilder()->rebuild();

        self::assertSame(self::sorted([[$card, $first], [$item, $first], [$card, $second], [$kept, $second]]), $this->storedUses());
        self::assertSame(['entries' => 2, 'verified' => 2, 'skipped' => 0, 'added' => 3, 'dry_run' => false], $result->toArray());
    }

    /**
     * Only an entry whose signature verifies is trusted: one whose content was
     * changed after it was signed, and one signed under a key the ring does not
     * hold, are skipped and add nothing.
     *
     * @return void
     */
    public function testOnlyRowsWhoseHmacVerifiesAreTrusted(): void
    {
        [$good, $tampered, $unknown, $planted] = [self::keyId(), self::keyId(), self::keyId(), self::keyId()];

        $kept    = $this->storeEntry(['card' => self::envelope($good)]);
        $changed = $this->storeEntry(['card' => self::envelope($tampered)]);
        $foreign = $this->storeEntry(['card' => self::envelope($unknown)]);

        $this->entries()->where('id', $changed)->update(['properties' => json_encode(['card' => self::envelope($planted)])]);
        $this->entries()->where('id', $foreign)->update(['key_id' => 'gone']);

        $result = $this->rebuilder()->rebuild();

        self::assertSame([[$good, $kept]], $this->storedUses());
        self::assertSame(['entries' => 3, 'verified' => 1, 'skipped' => 2, 'added' => 1, 'dry_run' => false], $result->toArray());
    }

    /**
     * A rebuild only adds: a key use no verified entry names, and one of an
     * entry that is not stored, are both left where they are, and a rebuild run
     * again adds nothing.
     *
     * @return void
     */
    public function testNothingIsEverRemoved(): void
    {
        $key   = self::keyId();
        $entry = $this->storeEntry(['card' => self::envelope($key)]);
        $stray = [[self::keyId(), $entry], [$key, Str::uuid7()->toString()]];

        $this->insertUses($stray);

        $first  = $this->rebuilder()->rebuild();
        $second = $this->rebuilder()->rebuild();

        self::assertSame(self::sorted([...$stray, [$key, $entry]]), $this->storedUses());
        self::assertSame(1, $first->added);
        self::assertSame(0, $second->added);
    }

    /**
     * A dry run reads and counts as a rebuild does, and writes nothing.
     *
     * @return void
     */
    public function testADryRunCountsOnly(): void
    {
        $this->storeEntry(['card' => self::envelope(self::keyId()), 'iban' => self::envelope(self::keyId())]);

        $result = $this->rebuilder()->rebuild(true);

        self::assertSame([], $this->storedUses());
        self::assertSame(['entries' => 1, 'verified' => 1, 'skipped' => 0, 'added' => 2, 'dry_run' => true], $result->toArray());
    }

    /**
     * The entries are read in pages of 1,000 by id, each page after the last id
     * of the one before, on the writer, and an entry with no envelope is
     * verified and adds nothing.
     *
     * @return void
     */
    public function testTheEntriesArePagedByTheirIds(): void
    {
        $finaliser = $this->finaliser();
        $codec     = new RowCodec;
        $rows      = [];

        for ($entry = 0; $entry <= KeyUseRebuilder::PAGE; $entry++) {
            $rows[] = $codec->encode($finaliser->finalise(RecordFactory::captured(['amount' => (string) $entry])));
        }

        foreach (array_chunk($rows, 20) as $chunk) {
            $this->entries()->insert($chunk);
        }

        /** @var \ArrayObject<int, string> $pages */
        $pages = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($pages): void {
            if (!str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            $pages->append($query->sql);
        });

        $result = $this->rebuilder()->rebuild();

        self::assertCount(2, $pages);
        self::assertStringNotContainsString('>', $pages->getArrayCopy()[0]);
        self::assertStringContainsString('>', $pages->getArrayCopy()[1]);
        self::assertSame(['entries' => 1001, 'verified' => 1001, 'skipped' => 0, 'added' => 0, 'dry_run' => false], $result->toArray());
    }

    /**
     * An empty entries table reads one page and adds nothing.
     *
     * @return void
     */
    public function testAnEmptyTableAddsNothing(): void
    {
        self::assertEquals(new KeyUseRebuildResult(0, 0, 0, 0, false), $this->rebuilder()->rebuild());
    }

    /**
     * Sign a captured record of the properties as the store signs it, insert it
     * as the store inserts it without its key uses, and return its id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $properties
     * @return string
     */
    private function storeEntry(array $properties): string
    {
        $record = $this->finaliser()->finalise(RecordFactory::captured($properties));

        $this->entries()->insert((new RowCodec)->encode($record));

        return $record->record->id;
    }

    /**
     * Insert the key uses, each as its key and its entry.
     *
     * @param  list<array{0: string, 1: string}>  $uses
     * @return void
     */
    private function insertUses(array $uses): void
    {
        $this->storageConnection()->table(KeyTables::keyUsesTable())->insert(array_map(static fn (array $use): array => ['key_id' => $use[0], 'entry_id' => $use[1]], $uses));
    }

    /**
     * Every stored key use, as its key and its entry, sorted.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function storedUses(): array
    {
        $stored = $this->storageConnection()->table(KeyTables::keyUsesTable())->get()->all();

        return self::sorted(array_map(static fn (object $use): array => [(string) $use->key_id, (string) $use->entry_id], $stored));
    }

    /**
     * A query of the entries table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function entries(): Builder
    {
        return $this->storageConnection()->table(EntrySettings::table());
    }

    /**
     * The rebuilder the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Keys\KeyUseRebuilder
     */
    private function rebuilder(): KeyUseRebuilder
    {
        return app(KeyUseRebuilder::class);
    }

    /**
     * The key uses sorted by key, then entry.
     *
     * @param  list<array{0: string, 1: string}>  $uses
     * @return list<array{0: string, 1: string}>
     */
    private static function sorted(array $uses): array
    {
        usort($uses, static fn (array $left, array $right): int => [$left[0], $left[1]] <=> [$right[0], $right[1]]);

        return $uses;
    }

    /**
     * An envelope naming the key.
     *
     * @param  string  $keyId
     * @return array{v: int, k: string, c: string}
     */
    private static function envelope(string $keyId): array
    {
        return ['v' => 1, 'k' => $keyId, 'c' => 'c2VhbGVkLWZpZWxkLXRleHQ'];
    }

    /**
     * A fresh key id.
     *
     * @return string
     */
    private static function keyId(): string
    {
        return Str::uuid7()->toString();
    }
}
