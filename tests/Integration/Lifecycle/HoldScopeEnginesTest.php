<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\TestCase;

/**
 * Integration tests for a hold scope's matching on whichever engine the suite
 * runs against: every dimension, and combinations of them, decided in PHP over
 * the rows the engine stored and returned, with and without tenants, actors,
 * subjects and batches, and with each time in the form the engine returns it,
 * trailing zeros trimmed or kept, so a hold keeps the same entries on SQLite,
 * MySQL and PostgreSQL.
 *
 * Rows are seeded with literal inserts of the columns the scope reads, so the
 * scope reads what the engine stored, not what the package wrote.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldScope::class)]
final class HoldScopeEnginesTest extends TestCase
{
    /** @var string An import batch's id. */
    private const string BATCH = '01932b4e-b000-7000-8000-000000000001';

    /** @var string Another import batch's id. */
    private const string OTHER_BATCH = '01932b4e-b000-7000-8000-000000000002';

    /** @var array<int, array<string, ?string>> The rows every test reads, by index: tenants, actors, subjects, categories, times and batches of every kind. */
    private const array ROWS = [
        1 => [
            'tenant_type'     => 'org',
            'tenant_id'       => 'a',
            'actor_type'      => 'user',
            'actor_id'        => '1',
            'subject_type'    => 'invoice',
            'subject_id'      => '1',
            'category'        => 'finance',
            'occurred_at'     => '2026-11-01 12:00:00.000000',
            'import_batch_id' => null,
        ],
        2 => [
            'tenant_type'     => 'org',
            'tenant_id'       => 'b',
            'actor_type'      => 'user',
            'actor_id'        => '2',
            'subject_type'    => 'invoice',
            'subject_id'      => '2',
            'category'        => 'security',
            'occurred_at'     => '2026-11-01 12:00:00.500000',
            'import_batch_id' => self::BATCH,
        ],
        3 => [
            'tenant_type'     => 'team',
            'tenant_id'       => 'a',
            'actor_type'      => 'user',
            'actor_id'        => '1',
            'subject_type'    => 'user',
            'subject_id'      => '2',
            'category'        => 'finance',
            'occurred_at'     => '2026-11-01 11:59:59.999999',
            'import_batch_id' => null,
        ],
        4 => [
            'tenant_type'     => null,
            'tenant_id'       => null,
            'actor_type'      => null,
            'actor_id'        => null,
            'subject_type'    => 'user',
            'subject_id'      => '1',
            'category'        => 'audit',
            'occurred_at'     => '2026-11-01 12:00:00.499999',
            'import_batch_id' => self::BATCH,
        ],
        5 => [
            'tenant_type'     => 'org',
            'tenant_id'       => null,
            'actor_type'      => 'user',
            'actor_id'        => '3',
            'subject_type'    => null,
            'subject_id'      => null,
            'category'        => 'finance',
            'occurred_at'     => '2026-11-02 00:00:00.000000',
            'import_batch_id' => self::OTHER_BATCH,
        ],
        6 => [
            'tenant_type'     => null,
            'tenant_id'       => null,
            'actor_type'      => 'user',
            'actor_id'        => '2',
            'subject_type'    => 'invoice',
            'subject_id'      => '1',
            'category'        => 'security',
            'occurred_at'     => '2026-10-31 00:00:00.000000',
            'import_batch_id' => null,
        ],
    ];

    /**
     * Rows of `[scope, the indexes of the rows it keeps]`: every dimension
     * alone, and combinations of them.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope, 1: list<int>}>
     */
    public static function provideScopes(): iterable
    {
        $at = static fn (string $time): CarbonImmutable => new CarbonImmutable($time, 'UTC');

        $every = static fn (): HoldScope => HoldScope::tenants(Reference::of('org', 'b'))
            ->withTenantless()
            ->about(Reference::of('user', '1'), Reference::of('user', '2'))
            ->categories('audit', 'security')
            ->occurredBetween($at('2026-11-01 12:00:00.499999'), $at('2026-11-01 12:00:00.500001'))
            ->importBatch(self::BATCH);

        $team = static fn (): HoldScope => HoldScope::tenants(Reference::of('org', 'b'), Reference::of('team', 'a'))
            ->categories('finance', 'security')
            ->about(Reference::of('user', '2'));

        yield from [
            'every entry'                      => [static fn (): HoldScope => HoldScope::all(), [1, 2, 3, 4, 5, 6]],
            'one tenant'                       => [static fn (): HoldScope => HoldScope::tenants(Reference::of('org', 'a')), [1]],
            'two tenants as pairs'             => [static fn (): HoldScope => HoldScope::tenants(Reference::of('org', 'a'), Reference::of('team', 'a')), [1, 3]],
            'a tenant and no tenant'           => [static fn (): HoldScope => HoldScope::tenants(Reference::of('org', 'a'))->withTenantless(), [1, 4, 6]],
            'no tenant'                        => [static fn (): HoldScope => HoldScope::tenantless(), [4, 6]],
            'a user as actor or subject'       => [static fn (): HoldScope => HoldScope::all()->about(Reference::of('user', '1')), [1, 3, 4]],
            'another user as actor or subject' => [static fn (): HoldScope => HoldScope::all()->about(Reference::of('user', '2')), [2, 3, 6]],
            'a category'                       => [static fn (): HoldScope => HoldScope::all()->categories('finance'), [1, 3, 5]],
            'a half-open window'               => [static fn (): HoldScope => HoldScope::all()->occurredBetween($at('2026-11-01 12:00:00'), $at('2026-11-01 12:00:00.5')), [1, 4]],
            'a window of open start'           => [static fn (): HoldScope => HoldScope::all()->occurredBetween(null, $at('2026-11-01 00:00:00.000000')), [6]],
            'a window of open end'             => [static fn (): HoldScope => HoldScope::all()->occurredBetween($at('2026-11-02 00:00:00.000000'), null), [5]],
            'an import batch'                  => [static fn (): HoldScope => HoldScope::all()->importBatch(self::BATCH), [2, 4]],
            'categories and a user'            => [static fn (): HoldScope => HoldScope::all()->categories('finance', 'security')->about(Reference::of('user', '2')), [2, 3, 6]],
            'tenants, categories and a user'   => [$team, [2, 3]],
            'no tenant of a batch'             => [static fn (): HoldScope => HoldScope::tenantless()->importBatch(self::BATCH), [4]],
            'a tenant of another batch'        => [static fn (): HoldScope => HoldScope::tenants(Reference::of('org', 'b'))->importBatch(self::OTHER_BATCH), []],
            'every dimension'                  => [$every, [2, 4]],
        ];
    }

    /**
     * Each scope keeps exactly the rows its dimensions match, read back from
     * the engine as it stored them.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  list<int>  $kept
     * @return void
     */
    #[DataProvider('provideScopes')]
    public function testMatchesReadsEveryEnginesStoredRow(\Closure $scope, array $kept): void
    {
        foreach (self::ROWS as $index => $columns) {
            self::insert($index, $columns);
        }

        $held   = $scope();
        $stored = self::entries()->orderBy('id')->get()->all();

        self::assertCount(count(self::ROWS), $stored);

        $matched = array_values(array_map(
            static fn (object $row): string => (string) ($row->id ?? ''),
            array_filter($stored, static fn (object $row): bool => $held->matches((array) $row)),
        ));

        self::assertSame(array_map(self::id(...), $kept), $matched);
    }

    /**
     * Every time the engine returns, trimmed or not, reads back as the instant
     * stored, to the microsecond, so the window compares what was stored.
     *
     * @return void
     */
    public function testEveryStoredTimeReadsBackToTheMicrosecond(): void
    {
        foreach (self::ROWS as $index => $columns) {
            self::insert($index, $columns);
        }

        foreach (self::entries()->get(['id', 'occurred_at'])->all() as $row) {
            $index = (int) hexdec(substr((string) $row->id, -12));

            self::assertSame(
                StoredTime::fromStorage(self::ROWS[$index]['occurred_at'] ?? ''),
                StoredTime::fromStorage((string) $row->occurred_at),
                "Row {$index} must read back as stored.",
            );
        }
    }

    /**
     * The id of the row of the index.
     *
     * @param  int  $index
     * @return string
     */
    private static function id(int $index): string
    {
        return sprintf('0192f5a0-7c1e-7000-8000-%012x', $index);
    }

    /**
     * Insert the row of the index, with the columns given over a valid row's.
     *
     * @param  int  $index
     * @param  array<string, ?string>  $columns
     * @return void
     */
    private static function insert(int $index, array $columns): void
    {
        self::entries()->insert([
            'id'                => self::id($index),
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'recorded_at'       => '2026-11-02 09:00:00.000000',
            'integrity_version' => 1,
            'key_id'            => 'k1',
            'hmac'              => str_repeat('0', 64),
            ...$columns,
        ]);
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function entries(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }
}
