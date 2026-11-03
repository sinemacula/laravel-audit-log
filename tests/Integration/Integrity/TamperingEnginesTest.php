<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for tampering on whichever engine the suite runs against,
 * each alteration made by a raw SQL statement that binds its values in the
 * engine's own column types (a `uuid`, a `json` document, a timestamp to the
 * microsecond): a modified entry, a deleted entry, a deleted seal, members
 * swapped between seals and a truncated tail are each found as they are on
 * every engine, and an entry's JSON that the engine stores in an order and a
 * spacing of its own, or that is rewritten so, still verifies, since integrity
 * is checked on the decoded values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Verifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class TamperingEnginesTest extends TestCase
{
    use TampersWithTheLog;

    /** @var string When the log is sealed. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every command runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var array<string, array<string, string>> The placeholder of each column type, by engine, that binds a value as that type. */
    private const array PLACEHOLDERS = [
        'pgsql' => ['uuid' => 'cast(? as uuid)', 'json' => 'cast(? as json)', 'time' => 'cast(? as timestamp(6))'],
        'mysql' => ['uuid' => '?', 'json' => 'cast(? as json)', 'time' => 'cast(? as datetime(6))'],
    ];

    /**
     * Register both commands, bind no anchor, nothing pruned and a clock
     * stopped when every command runs, and seal at a fixed time.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->registerIntegrityCommands();

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * On each engine, an entry's properties replaced by a JSON document of the
     * engine's type, and another entry's time moved by one microsecond in the
     * engine's timestamp type, each no longer match the entry's HMAC.
     *
     * @return void
     */
    public function testAModifiedEntryIsTampered(): void
    {
        $seals   = $this->sealLog(2);
        $first   = $this->membersOf((string) $seals[0]['id'])[0];
        $second  = $this->membersOf((string) $seals[1]['id'])[1];
        $entries = $this->wrapped(EntrySettings::table());

        $uuid = $this->typed('uuid');

        $this->connection()->update(sprintf('update %s set properties = %s where id = %s', $entries, $this->typed('json'), $uuid), ['{"amount": "1.00"}', $first]);
        $this->connection()->update(sprintf('update %s set occurred_at = %s where id = %s', $entries, $this->typed('time'), $uuid), ['2026-11-01 12:01:00.000002', $second]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(self::line(1, (string) $seals[0]['id'], 'tampered', $first), $output);
        self::assertStringContainsString(self::line(2, (string) $seals[1]['id'], 'tampered', $second), $output);
    }

    /**
     * On each engine, a sealed entry deleted by a raw statement leaves its seal
     * incomplete, naming it.
     *
     * @return void
     */
    public function testADeletedEntryIsIncomplete(): void
    {
        $seals = $this->sealLog(1);
        $entry = $this->membersOf((string) $seals[0]['id'])[1];

        $this->connection()->delete(sprintf('delete from %s where id = %s', $this->wrapped(EntrySettings::table()), $this->typed('uuid')), [$entry]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        $line = sprintf("seal 1 %s integrity=incomplete anchoring=unanchored members=2 finding=missing_entry first=%s\n", $seals[0]['id'], $entry);

        self::assertStringContainsString($line, $output);
    }

    /**
     * On each engine, a seal row deleted by a raw statement leaves a gap where
     * the walk expected it and its member rows orphaned.
     *
     * @return void
     */
    public function testADeletedSealIsTampered(): void
    {
        $seals   = $this->sealLog(3);
        $members = $this->membersOf((string) $seals[1]['id']);

        $this->connection()->delete(sprintf('delete from %s where sequence = ?', $this->wrapped(IntegrityTables::checkpointsTable())), [2]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        $line = sprintf("seal 3 %s integrity=tampered anchoring=unanchored members=2 finding=sequence_gap first=%s\n", $seals[2]['id'], $seals[2]['id']);

        self::assertStringContainsString($line, $output);
        self::assertStringContainsString(sprintf("finding orphan_member integrity=tampered count=2 first=%s\n", $members[0]), $output);
    }

    /**
     * On each engine, a member of one seal swapped with a member of another by
     * raw statements breaks both members digests.
     *
     * @return void
     */
    public function testMembersSwappedBetweenSealsAreTampered(): void
    {
        $seals   = $this->sealLog(2);
        $first   = (string) $seals[0]['id'];
        $second  = (string) $seals[1]['id'];
        $moving  = [$this->membersOf($first)[0], $this->membersOf($second)[0]];
        $members = sprintf('update %s set checkpoint_id = %s where entry_id = %s', $this->wrapped(IntegrityTables::membersTable()), $this->typed('uuid'), $this->typed('uuid'));

        $this->connection()->update($members, [$second, $moving[0]]);
        $this->connection()->update($members, [$first, $moving[1]]);

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString(sprintf("seal 1 %s integrity=tampered anchoring=unanchored members=2 finding=members_digest first=%s\n", $first, $first), $output);
        self::assertStringContainsString(sprintf("seal 2 %s integrity=tampered anchoring=unanchored members=2 finding=members_digest first=%s\n", $second, $second), $output);
    }

    /**
     * On each engine, the last seal deleted with its members and entries by raw
     * statements, and every local receipt cleared, is still found against the
     * anchor's head.
     *
     * @return void
     */
    public function testTailTruncationIsTampered(): void
    {
        $this->useDiskAnchor();

        $seals = $this->sealLog(3);

        self::assertSame(0, $this->runSeal()[0], 'The log could not be anchored.');

        $tail    = (string) $seals[2]['id'];
        $members = $this->wrapped(IntegrityTables::membersTable());
        $uuid    = $this->typed('uuid');

        $entries = $this->wrapped(EntrySettings::table());

        $this->connection()->delete(sprintf('delete from %s where id in (select entry_id from %s where checkpoint_id = %s)', $entries, $members, $uuid), [$tail]);
        $this->connection()->delete(sprintf('delete from %s where checkpoint_id = %s', $members, $uuid), [$tail]);
        $this->connection()->delete(sprintf('delete from %s where id = %s', $this->wrapped(IntegrityTables::checkpointsTable()), $uuid), [$tail]);
        $this->connection()->update(sprintf('update %s set anchor = null, anchor_receipt = null, anchored_at = null', $this->wrapped(IntegrityTables::checkpointsTable())));

        [$exit, $output] = $this->verify();

        self::assertSame(1, $exit);
        self::assertStringContainsString("finding missing_tail integrity=tampered count=1 first=none\n", $output);
        self::assertStringContainsString("Checked seals 1 to 2 of head 2; the anchor's head is 3.\n", $output);
        self::assertStringContainsString("Unsealed: 0 pending, 0 overdue.\n", $output);
    }

    /**
     * On each engine, an entry whose properties the engine may store with its
     * keys reordered, nested and in a list, verifies, and still verifies once
     * its JSON is rewritten by a raw statement with its keys in another order
     * and other spacing, since integrity is checked on the decoded values; a
     * list's order, which is part of the value, is not excused.
     *
     * @return void
     */
    public function testAJsonRoundTripStillVerifies(): void
    {
        $entry = $this->storeEntryWith(['zeta' => 'last', 'a' => ['longer' => 'x', 'b' => 'y'], 'list' => ['3', '1', '2']]);

        $this->sealAll();

        $seal   = $this->sealIdAt(1);
        $update = sprintf('update %s set properties = %s where id = %s', $this->wrapped(EntrySettings::table()), $this->typed('json'), $this->typed('uuid'));

        self::assertSame([0, sprintf("seal 1 %s integrity=valid anchoring=unanchored members=1\n", $seal)], $this->firstLine());

        $this->connection()->update($update, ["{ \"list\" : [\"3\", \"1\", \"2\"],\n  \"a\": {\"b\":\"y\", \"longer\":\"x\"}, \"zeta\":\"last\" }", $entry]);

        self::assertSame([0, sprintf("seal 1 %s integrity=valid anchoring=unanchored members=1\n", $seal)], $this->firstLine());

        $this->connection()->update($update, ['{"zeta": "last", "a": {"longer": "x", "b": "y"}, "list": ["1", "2", "3"]}', $entry]);

        self::assertSame([1, sprintf("seal 1 %s integrity=tampered anchoring=unanchored members=1 finding=entry_hmac first=%s\n", $seal, $entry)], $this->firstLine());
    }

    /**
     * Run `audit-log:verify` and return its exit code and the first line it
     * printed, with its line break.
     *
     * @return array{0: int, 1: string}
     */
    private function firstLine(): array
    {
        [$exit, $output] = $this->verify();

        return [$exit, explode("\n", $output)[0] . "\n"];
    }

    /**
     * Store one finalised record with the properties given, recorded when the
     * first entries are, and return its id.
     *
     * @param  array<string, array<string, string>|list<string>|string>  $properties
     * @return string
     */
    private function storeEntryWith(array $properties): string
    {
        $instant   = StoredTime::format(new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC'));
        $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));
        $record    = $finaliser->finalise(RecordFactory::captured($properties, occurredAt: $instant));

        app(DatabaseAuditStore::class)->store($record);

        return $record->record->id;
    }

    /**
     * The placeholder that binds a value as the column type on this engine:
     * cast on PostgreSQL and, for JSON and times, on MySQL, and bound as given
     * on SQLite, which keeps every value as written.
     *
     * @param  'json'|'time'|'uuid'  $type
     * @return string
     */
    private function typed(string $type): string
    {
        return self::PLACEHOLDERS[$this->connection()->getDriverName()][$type] ?? '?';
    }

    /**
     * The table's name as this engine quotes it, with the connection's prefix.
     *
     * @param  string  $table
     * @return string
     */
    private function wrapped(string $table): string
    {
        return $this->connection()->getQueryGrammar()->wrapTable($table);
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * The line the verify command prints for a seal of two members whose first
     * altered entry is the one given.
     *
     * @param  int  $sequence
     * @param  string  $id
     * @param  string  $integrity
     * @param  string  $entry
     * @return string
     */
    private static function line(int $sequence, string $id, string $integrity, string $entry): string
    {
        return sprintf("seal %d %s integrity=%s anchoring=unanchored members=2 finding=entry_hmac first=%s\n", $sequence, $id, $integrity, $entry);
    }
}
