<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\TestCase;

/**
 * Integration tests for the operational progress of sealing, anchoring and
 * verification, on whichever engine the suite runs against: what a name reads
 * as when it is missing or malformed, what a write stores and replaces, the
 * time it keeps, the names it refuses, and that every statement reaches the
 * writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityProgress::class)]
final class IntegrityProgressTest extends TestCase
{
    use InteractsWithReadWriteSplit;

    /** @var string Absolute path to the shipped integrity state migration file. */
    private const string STATE_MIGRATION = __DIR__ . '/../../../database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php';

    /** @var string A time progress is written at, in UTC. */
    private const string AT = '2026-11-01 12:00:00.123456';

    /**
     * Close the split's connections and delete their files, when a test made
     * them.
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
     * A name with no row reads as `null`.
     *
     * @return void
     */
    public function testAMissingNameIsNull(): void
    {
        self::assertNull($this->progress()->get(IntegrityProgress::SEAL_LAST));
    }

    /**
     * A map of scalars written under a name reads back as written, stored as a
     * JSON object with its slashes and its Unicode unescaped, with the time it
     * was written.
     *
     * @return void
     */
    public function testPutThenGetRoundTrips(): void
    {
        $value = ['sequence' => 42, 'id' => '01932b4e-9000-7000-8000-000000000001', 'path' => 'a/b', 'note' => 'café', 'ratio' => 1.5, 'sweep' => true, 'class' => null];

        $this->progress()->put(IntegrityProgress::SEAL_LAST, $value, self::at());

        self::assertSame($value, $this->progress()->get(IntegrityProgress::SEAL_LAST));

        $row = DB::table(IntegrityTables::stateTable())->first(['name', 'value', 'updated_at']);

        self::assertNotNull($row);
        self::assertSame(IntegrityProgress::SEAL_LAST, $row->name);
        self::assertSame('{"sequence":42,"id":"01932b4e-9000-7000-8000-000000000001","path":"a/b","note":"café","ratio":1.5,"sweep":true,"class":null}', $row->value);
        self::assertSame(self::AT, $row->updated_at);
    }

    /**
     * An empty map is stored as an empty JSON object, so it reads back as an
     * empty map rather than as absent.
     *
     * @return void
     */
    public function testAnEmptyMapRoundTrips(): void
    {
        $this->progress()->put(IntegrityProgress::SWEEP_COMPLETED, [], self::at());

        self::assertSame([], $this->progress()->get(IntegrityProgress::SWEEP_COMPLETED));
        self::assertSame('{}', DB::table(IntegrityTables::stateTable())->value('value'));
    }

    /**
     * A second write under a name replaces the first, value and time, in the
     * one row the name has, and leaves every other name as it was.
     *
     * @return void
     */
    public function testASecondPutReplacesTheFirst(): void
    {
        $progress = $this->progress();

        $progress->put(IntegrityProgress::SWEEP_CURSOR, ['recorded_at' => '2026-10-31T23:35:00.000001Z', 'id' => 'a'], self::at());
        $progress->put(IntegrityProgress::ANCHOR_LAST, ['sequence' => 1], self::at());
        $progress->put(IntegrityProgress::SWEEP_CURSOR, ['recorded_at' => '2026-11-01T00:00:00.000002Z'], self::at('2026-11-01 12:05:00.654321'));

        self::assertSame(['recorded_at' => '2026-11-01T00:00:00.000002Z'], $progress->get(IntegrityProgress::SWEEP_CURSOR));
        self::assertSame(['sequence' => 1], $progress->get(IntegrityProgress::ANCHOR_LAST));

        $rows = DB::table(IntegrityTables::stateTable())->where('name', IntegrityProgress::SWEEP_CURSOR)->get(['updated_at'])->all();

        self::assertCount(1, $rows);
        self::assertSame('2026-11-01 12:05:00.654321', $rows[0]->updated_at);
        self::assertSame(2, DB::table(IntegrityTables::stateTable())->count());
    }

    /**
     * The time is stored in UTC to the microsecond, whatever zone it was given
     * in.
     *
     * @return void
     */
    public function testTheTimeIsKeptToTheMicrosecond(): void
    {
        $at = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-11-01 17:30:00.000007', new \DateTimeZone('Asia/Kolkata'));

        self::assertInstanceOf(\DateTimeImmutable::class, $at);

        $this->progress()->put(IntegrityProgress::VERIFY_LAST_FULL, ['head' => 3, 'passed' => true], $at);

        self::assertSame('2026-11-01 12:00:00.000007', DB::table(IntegrityTables::stateTable())->value('updated_at'));
        self::assertSame('Asia/Kolkata', $at->getTimezone()->getName());
    }

    /**
     * Rows of `[raw value]`: stored values that are not a JSON object of
     * scalars.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield from [
            'an empty list'    => ['[]'],
            'a list'           => ['[1,2]'],
            'a string'         => ['"x"'],
            'a number'         => ['1'],
            'JSON null'        => ['null'],
            'a nested object'  => ['{"a":{"b":1}}'],
            'a nested list'    => ['{"a":[1]}'],
            'not JSON'         => ['not json'],
            'an empty string'  => [''],
            'a truncated map'  => ['{"a":1'],
            'a lone surrogate' => ['{"a":"\ud800"}'],
            'a trailing comma' => ['{"a":1,}'],
        ];
    }

    /**
     * A stored value that is not a JSON object of scalars reads as absent, and
     * the next write under the name replaces it.
     *
     * @param  string  $raw
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testAMalformedValueReadsAsAbsent(string $raw): void
    {
        DB::table(IntegrityTables::stateTable())->insert(['name' => IntegrityProgress::ANCHOR_LAST_FAILURE, 'value' => $raw, 'updated_at' => self::AT]);

        $progress = $this->progress();

        self::assertNull($progress->get(IntegrityProgress::ANCHOR_LAST_FAILURE));

        $progress->put(IntegrityProgress::ANCHOR_LAST_FAILURE, ['class' => \RuntimeException::class], self::at());

        self::assertSame(['class' => \RuntimeException::class], $progress->get(IntegrityProgress::ANCHOR_LAST_FAILURE));
    }

    /**
     * Forgetting a name removes its row and no other, and forgetting a name
     * with no row does nothing.
     *
     * @return void
     */
    public function testForgetRemovesTheRow(): void
    {
        $progress = $this->progress();

        $progress->put(IntegrityProgress::SWEEP_CURSOR, ['id' => 'a'], self::at());
        $progress->put(IntegrityProgress::SEAL_LAST_RUN, ['seals' => 0], self::at());

        $progress->forget(IntegrityProgress::SWEEP_CURSOR);
        $progress->forget(IntegrityProgress::SWEEP_COMPLETED);

        self::assertNull($progress->get(IntegrityProgress::SWEEP_CURSOR));
        self::assertSame(['seals' => 0], $progress->get(IntegrityProgress::SEAL_LAST_RUN));
        self::assertSame([IntegrityProgress::SEAL_LAST_RUN], DB::table(IntegrityTables::stateTable())->pluck('name')->all());
    }

    /**
     * Every name the package uses is accepted, each under its own row.
     *
     * @return void
     */
    public function testEveryOwnNameIsAccepted(): void
    {
        $names = [
            IntegrityProgress::SEAL_LAST_RUN       => 'seal.last_run',
            IntegrityProgress::SEAL_LAST           => 'seal.last',
            IntegrityProgress::SWEEP_CURSOR        => 'sweep.cursor',
            IntegrityProgress::SWEEP_COMPLETED     => 'sweep.completed',
            IntegrityProgress::ANCHOR_LAST         => 'anchor.last',
            IntegrityProgress::ANCHOR_LAST_FAILURE => 'anchor.last_failure',
            IntegrityProgress::VERIFY_LAST_FULL    => 'verify.last_full',
        ];

        $progress = $this->progress();

        foreach ($names as $name => $expected) {
            self::assertSame($expected, $name);

            $progress->put($name, ['name' => $name], self::at());

            self::assertSame(['name' => $name], $progress->get($name), $name);
        }

        self::assertSame(7, DB::table(IntegrityTables::stateTable())->count());
    }

    /**
     * Rows of `[name]`: names that are not the package's own, including near
     * misses of its own.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideForeignNames(): iterable
    {
        yield from [
            'empty'             => [''],
            'unknown'           => ['seal.next'],
            'a capital'         => ['Seal.last'],
            'a trailing space'  => ['seal.last '],
            'a prefix'          => ['seal'],
            'a suffix'          => ['verify.last_full.x'],
            'the constant name' => ['SEAL_LAST'],
        ];
    }

    /**
     * A name that is not the package's own is refused by reading, writing and
     * forgetting alike, before any statement, and nothing is written.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideForeignNames')]
    public function testRefusesANameThatIsNotThePackagesOwn(string $name): void
    {
        $progress = $this->progress();

        $calls = [
            'get'    => static fn () => $progress->get($name),
            'put'    => static fn () => $progress->put($name, ['a' => 1], self::at()),
            'forget' => static fn () => $progress->forget($name),
        ];

        foreach ($calls as $method => $call) {
            try {
                $call();
                self::fail('Expected ' . $method . '() to refuse the name.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An integrity progress name must be one of the package\'s own.', $exception->getMessage(), $method);
            }
        }

        self::assertSame(0, DB::table(IntegrityTables::stateTable())->count());
    }

    /**
     * A value JSON cannot encode is refused with the encoder's exception, and
     * nothing is written.
     *
     * @return void
     */
    public function testAValueJsonCannotEncodeIsRefused(): void
    {
        try {
            $this->progress()->put(IntegrityProgress::SEAL_LAST_RUN, ['ratio' => NAN], self::at());
            self::fail('Expected the value to be refused.');
        } catch (\JsonException) {
            self::assertSame(0, DB::table(IntegrityTables::stateTable())->count());
        }
    }

    /**
     * Progress goes to the configured state table on the storage connection.
     *
     * @return void
     */
    public function testUsesTheConfiguredStateTable(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.state_table', 'audit_progress_elsewhere');

        $this->stateMigration()->up(); // @phpstan-ignore method.notFound

        try {
            $this->progress()->put(IntegrityProgress::SEAL_LAST, ['sequence' => 9], self::at());

            self::assertSame(1, DB::table('audit_progress_elsewhere')->count());
            self::assertSame(0, DB::table(IntegrityTables::DEFAULT_STATE)->count());
            self::assertSame(['sequence' => 9], $this->progress()->get(IntegrityProgress::SEAL_LAST));
        } finally {
            $this->stateMigration()->down(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * On a read/write split storage connection whose replica lags, a read finds
     * a row on the primary alone and ignores one on the replica alone, and a
     * write or a removal reaches the primary and never the replica.
     *
     * @return void
     */
    public function testReadsAndWritesTheWriter(): void
    {
        $this->useReadWriteSplit();
        $this->migrateTheStateOnTheSplit();

        $table   = IntegrityTables::stateTable();
        $primary = DB::connection(self::PRIMARY_CONNECTION)->table($table);
        $replica = DB::connection(self::REPLICA_CONNECTION)->table($table);

        $primary->insert(['name' => IntegrityProgress::SEAL_LAST, 'value' => '{"sequence":7}', 'updated_at' => self::AT]);
        $replica->insert(['name' => IntegrityProgress::ANCHOR_LAST, 'value' => '{"sequence":3}', 'updated_at' => self::AT]);

        $progress = $this->progress();

        self::assertSame(['sequence' => 7], $progress->get(IntegrityProgress::SEAL_LAST));
        self::assertNull($progress->get(IntegrityProgress::ANCHOR_LAST));

        $progress->put(IntegrityProgress::VERIFY_LAST_FULL, ['passed' => true], self::at());

        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('name', IntegrityProgress::VERIFY_LAST_FULL)->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table($table)->where('name', IntegrityProgress::VERIFY_LAST_FULL)->count());

        $progress->forget(IntegrityProgress::SEAL_LAST);

        self::assertSame(0, DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('name', IntegrityProgress::SEAL_LAST)->count());
        self::assertSame(1, DB::connection(self::REPLICA_CONNECTION)->table($table)->where('name', IntegrityProgress::ANCHOR_LAST)->count());
    }

    /**
     * The progress gateway, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Database\IntegrityProgress
     */
    private function progress(): IntegrityProgress
    {
        return app(IntegrityProgress::class);
    }

    /**
     * The time progress is written at: `AT`, or the given UTC time.
     *
     * @param  string  $at
     * @return \DateTimeImmutable
     */
    private static function at(string $at = self::AT): \DateTimeImmutable
    {
        $time = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', $at, new \DateTimeZone('UTC'));

        self::assertInstanceOf(\DateTimeImmutable::class, $time);

        return $time;
    }

    /**
     * Migrate the state table on the split's primary and replica, as the trait
     * migrates the entries table, and leave the split the storage connection.
     *
     * @return void
     */
    private function migrateTheStateOnTheSplit(): void
    {
        $config    = app(ConfigRepository::class);
        $migration = $this->stateMigration();

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);
            $migration->up(); // @phpstan-ignore method.notFound
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);
    }

    /**
     * Require the shipped integrity state migration file and return the
     * resulting `Migration` instance.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function stateMigration(): Migration
    {
        $migration = include self::STATE_MIGRATION;

        if (!$migration instanceof Migration) {
            self::fail('Integrity state migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
