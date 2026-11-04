<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\ReadTerms;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Reads the trail as an application does and inspects what each read leaves:
 * the read path's bindings, defaults that the provider's own bindings make a
 * no-op of; an access policy answered by a closure, or one that sees every
 * entry or the entries of some tenants; entries seeded through the database
 * store, signed as the package signs them; the records of the package's own
 * codes, decoded as stored, and their properties compared as the engine keeps
 * them; the plaintext of a read's disclosure; the viewer
 * the tests read for; and the statements run on any connection.
 *
 * A seeded entry is a captured record of an approved invoice, in the `finance`
 * category, by `user` 42 on `invoice` `inv_0042` for `organisation` `org_01`,
 * with the fields given, under their stored, snake_case keys, in place of its
 * own; it occurs and is recorded at the instant given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsTheTrail
{
    /** @var string When the first of the entries seeded together occurs. */
    protected const string FIRST_SEEDED_AT = '2026-11-01T12:00:00.000000Z';

    /** @var list<\Illuminate\Database\Events\QueryExecuted> The statements run since capturing began, in order. */
    private array $capturedQueries = [];

    /** @var bool Whether statements are being captured. */
    private bool $capturingQueries = false;

    /**
     * Bind what reading the trail needs where nothing has bound it yet: the
     * scoped read guard, the sealed field reader and the deny-all policy.
     *
     * @return void
     */
    protected function bindReading(): void
    {
        app()->scopedIf(ReadGuard::class);
        app()->singletonIf(FieldReader::class, SealedFieldReader::class);
        app()->singletonIf(AuditAccessPolicy::class, DenyAllPolicy::class);
    }

    /**
     * Bind an access policy answering with the closure, and return it so a test
     * can read what it was asked.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference, \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose): \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return \Tests\Fixtures\Querying\ClosurePolicy
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    protected function usePolicy(\Closure $scope): ClosurePolicy
    {
        $policy = new ClosurePolicy($scope);

        app()->instance(AuditAccessPolicy::class, $policy);

        return $policy;
    }

    /**
     * Bind an access policy that lets every viewer see every entry.
     *
     * @return void
     */
    protected function allowEverything(): void
    {
        $this->usePolicy(static fn (): AccessScope => AccessScope::all());
    }

    /**
     * Bind an access policy that lets every viewer see the entries of the
     * tenants alone.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$tenants
     * @return void
     */
    protected function allowTenants(Reference ...$tenants): void
    {
        $this->usePolicy(static fn (): AccessScope => AccessScope::tenants(...$tenants));
    }

    /**
     * Store a captured record through the database store, with the fields given
     * in place of its own, occurring and recorded at the instant given or
     * `RecordFactory::OCCURRED_AT`, under the id given or a fresh one, and
     * return its id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @param  ?string  $occurredAt
     * @param  ?string  $id
     * @return string
     */
    protected function seedEntry(array $fields = [], ?string $occurredAt = null, ?string $id = null): string
    {
        $occurredAt ??= RecordFactory::OCCURRED_AT;

        $record    = RecordFactory::withFields($fields, RecordFactory::captured(id: $id, occurredAt: $occurredAt));
        $finalised = (new RecordFinaliser(FrozenClock::at($occurredAt), app(RecordSigner::class)))->finalise($record);

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * Store the number of captured records, each with the fields given, the
     * first occurring at `FIRST_SEEDED_AT` and each next one a microsecond
     * later, and return their ids, newest last.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $count
     * @param  array<string, mixed>  $fields
     * @return list<string>
     */
    protected function seedEntries(int $count, array $fields = []): array
    {
        $first = new CarbonImmutable(self::FIRST_SEEDED_AT, 'UTC');
        $ids   = [];

        for ($index = 0; $index < $count; $index++) {
            $ids[] = $this->seedEntry($fields, StoredTime::format($first->addMicroseconds($index)));
        }

        return $ids;
    }

    /**
     * Every stored record of a package code, or of the one code given, decoded
     * through the row codec, in the order they were recorded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?string  $code
     * @return list<array<string, mixed>>
     */
    protected function readRecords(?string $code = null): array
    {
        $rows = DB::connection(StorageConnection::name())
            ->table(EntrySettings::table())
            ->orderBy('recorded_at')
            ->orderBy('id')
            ->get()
            ->all();

        $codec   = new RowCodec;
        $records = [];

        foreach ($rows as $row) {
            $event = $row->event ?? null;

            if (!is_string($event) || !str_starts_with($event, EventCode::RESERVED_PREFIX) || ($code !== null && $event !== $code)) {
                continue;
            }

            $records[] = $codec->decode((array) $row);
        }

        return $records;
    }

    /**
     * The properties of a record `readRecords()` gave, with their maps as
     * arrays.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $record
     * @return array<array-key, mixed>
     */
    protected static function propertiesOf(array $record): array
    {
        $properties = json_decode(json_encode($record['properties'] ?? null, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($properties);

        return $properties;
    }

    /**
     * Assert stored properties, or a part of them, are the expected ones:
     * identical, key order included, where the storage connection keeps the
     * order a JSON object's keys were written in, and identical but for that
     * order on MySQL, whose JSON column stores every object with its keys
     * sorted. A list keeps its order on every engine.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $expected
     * @param  mixed  $actual
     * @return void
     */
    protected static function assertSameProperties(mixed $expected, mixed $actual): void
    {
        if (!self::doesStorageSortJsonKeys()) {
            self::assertSame($expected, $actual);

            return;
        }

        self::assertSame(self::withSortedKeys($expected), self::withSortedKeys($actual));
    }

    /**
     * Assert stored properties have exactly the expected keys: in the order
     * given where the storage connection keeps the order a JSON object's keys
     * were written in, and in any order on MySQL, which sorts them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<string>  $expected
     * @param  array<array-key, mixed>  $properties
     * @return void
     */
    protected static function assertSamePropertyKeys(array $expected, array $properties): void
    {
        $keys = array_keys($properties);

        if (self::doesStorageSortJsonKeys()) {
            sort($expected);
            sort($keys);
        }

        self::assertSame($expected, $keys);
    }

    /**
     * The plaintext of the artifact the entry carries, decrypted under the
     * application's key and decoded with its maps as arrays; the artifact must
     * exist.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $entryId
     * @return array<array-key, mixed>
     */
    protected function disclosureOf(string $entryId): array
    {
        $members = DB::connection(StorageConnection::name())->table(EntrySettings::artifactsTable())->where('entry_id', $entryId)->value('members');

        self::assertIsString($members, "No artifact is stored for {$entryId}.");

        $plaintext = json_decode(app(StringEncrypter::class)->decryptString($members), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($plaintext);

        return $plaintext;
    }

    /**
     * The terms a read under the filters and the scope is recorded with, its
     * fingerprints keyed under the ring's signing key, as the read path makes
     * them.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadTerms
     */
    protected static function termsOf(?TrailFilters $filters, ?AccessScope $scope): ReadTerms
    {
        return ReadTerms::of(app(KeyRing::class)->signingKey(), $filters ?? TrailFilters::none(), $scope);
    }

    /**
     * The viewer the tests read the trail for.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    protected function viewer(): Reference
    {
        return Reference::of('App\Models\User', '7');
    }

    /**
     * Capture every statement run on any connection from here on, forgetting
     * any captured before.
     *
     * @return void
     */
    protected function captureQueries(): void
    {
        $this->capturedQueries = [];

        if ($this->capturingQueries) {
            return;
        }

        $this->capturingQueries = true;

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->capturedQueries[] = $query;
        });
    }

    /**
     * The statements run since capturing began, in order.
     *
     * @return list<\Illuminate\Database\Events\QueryExecuted>
     */
    protected function capturedQueries(): array
    {
        return $this->capturedQueries;
    }

    /**
     * The statements run since capturing began that read the entries table, as
     * their SQL, in order.
     *
     * @return list<string>
     */
    protected function entryReads(): array
    {
        $table = EntrySettings::table();
        $reads = [];

        foreach ($this->capturedQueries as $query) {
            if (!str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, $table)) {
                continue;
            }

            $reads[] = $query->sql;
        }

        return $reads;
    }

    /**
     * Whether the storage connection's JSON column sorts the keys of every
     * object it stores, as MySQL's binary JSON does.
     *
     * @return bool
     */
    private static function doesStorageSortJsonKeys(): bool
    {
        return DB::connection(StorageConnection::name())->getDriverName() === 'mysql';
    }

    /**
     * The value with the keys of every map within it sorted, each list kept in
     * its order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function withSortedKeys(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        $sorted = array_map(self::withSortedKeys(...), $value);

        if (!array_is_list($sorted)) {
            ksort($sorted, SORT_STRING);
        }

        return $sorted;
    }
}
