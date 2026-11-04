<?php

declare(strict_types = 1);

namespace Tests\Integration\Access;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use Tests\TestCase;

/**
 * Integration tests for a code prefix on whichever engine the suite runs
 * against: the prefix is matched with an explicit `like` and its own escape
 * character, so a literal underscore matches only an underscore, a prefix
 * matches only the codes beneath it, and SQLite reads it as `like`, never as
 * the case-sensitive `glob` the framework's own `like` becomes there.
 *
 * Rows are seeded with literal inserts, so the statements read what the engine
 * stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeCompiler::class)]
final class LikeEscapingTest extends TestCase
{
    /**
     * A prefix holding an underscore matches the code with an underscore there,
     * and not one with any other character in its place.
     *
     * @return void
     */
    public function testALiteralUnderscoreMatchesOnlyAnUnderscore(): void
    {
        self::insert(1, 'app.a_b.x');
        self::insert(2, 'app.axb.y');
        self::insert(3, 'app.a_bc.z');

        self::assertSame(['app.a_b.x'], self::eventsUnder('app.a_b.'));
        self::assertSame(['app.a_b.x', 'app.a_bc.z', 'app.axb.y'], self::eventsUnder('app.'));
    }

    /**
     * A prefix matches only the codes beneath it, never a code whose first
     * segment merely begins the same way.
     *
     * @return void
     */
    public function testAPrefixMatchesOnlyItsDescendants(): void
    {
        self::insert(1, 'apple.x');
        self::insert(2, 'app.x');
        self::insert(3, 'app.x.y');
        self::insert(4, 'xapp.x');

        self::assertSame(['app.x', 'app.x.y'], self::eventsUnder('app.'));
        self::assertSame(['app.x.y'], self::eventsUnder('app.x.'));
    }

    /**
     * The clause is the explicit `like` with the `!` escape, never `glob`, on
     * every engine, SQLite included, and it finds what it should there.
     *
     * @return void
     */
    public function testTheClauseIsNotGlobOnSqlite(): void
    {
        self::insert(1, 'app.a_b.x');
        self::insert(2, 'app.aab.x');

        $query = (new ScopeCompiler)->apply(self::entries(), AccessScope::all(), TrailFilters::none()->withEventPrefix('app.a_b.'));
        $sql   = $query->toSql();

        self::assertStringContainsString('like ? escape \'!\'', $sql);
        self::assertStringNotContainsStringIgnoringCase('glob', $sql);
        self::assertSame(['app.a!_b.%'], $query->getBindings());
        self::assertSame(['app.a_b.x'], array_values(array_map(strval(...), $query->pluck('event')->all())));
    }

    /**
     * The codes of the rows beneath the prefix, sorted bytewise here rather
     * than by an engine's collation.
     *
     * @param  string  $prefix
     * @return list<string>
     */
    private static function eventsUnder(string $prefix): array
    {
        $events = (new ScopeCompiler)
            ->apply(self::entries(), AccessScope::all(), TrailFilters::none()->withEventPrefix($prefix))
            ->pluck('event')
            ->all();

        $events = array_values(array_map(strval(...), $events));

        sort($events, SORT_STRING);

        return $events;
    }

    /**
     * Insert a row of the index with the code.
     *
     * @param  int  $index
     * @param  string  $event
     * @return void
     */
    private static function insert(int $index, string $event): void
    {
        self::entries()->insert([
            'id'                => sprintf('0192f5a0-7c1e-7000-8000-%012x', $index),
            'record_version'    => 1,
            'event'             => $event,
            'event_version'     => 1,
            'category'          => 'general',
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => '2026-11-01 12:00:00.000000',
            'recorded_at'       => '2026-11-01 12:00:00.000000',
            'integrity_version' => 1,
            'key_id'            => 'k1',
            'hmac'              => str_repeat('0', 64),
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
