<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\MassAssignmentException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Casts\UtcInstant;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Models\ImmutableEntryException;
use Tests\TestCase;

/**
 * Feature tests for the read model: the table and connection it reads, its key,
 * the casts it reads columns through, and every write through Eloquent refused
 * before an event fires or a statement runs, with a drift guard over the
 * installed model's write methods; only the query builder writes, as
 * documented.
 *
 * Rows are seeded with literal `DB::table()` inserts, never through the store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditEntry::class)]
#[CoversClass(UtcInstant::class)]
final class AuditEntryTest extends TestCase
{
    /** @var string The table the entries live in. */
    private const string TABLE = 'audit_log_entries';

    /** @var string The id of the seeded entry. */
    private const string ID = '0192f5a0-7c1e-7000-8000-000000000001';

    /** @var string The id of an entry that was never stored. */
    private const string NEW_ID = '0192f5a0-7c1e-7000-8000-000000000002';

    /** @var string Why a write through the model is refused, for the method it names. */
    private const string MESSAGE = 'Audit entries are append-only: `%s()` cannot write an entry; the store writes entries, and the database\'s grants keep them unchanged.';

    /** @var string The write statements a refused write must never issue. */
    private const string WRITE_STATEMENT = '/\A\s*(insert|update|delete|replace|merge|upsert|truncate)\b/i';

    /** @var string The installed model's methods whose names say they may write. */
    private const string WRITE_METHOD = '/\A(save|update|push|touch|delete|forceDelete|destroy|forceDestroy|create|forceCreate|increment|decrement|perform)/';

    /** @var array<string, string> The installed model's write methods the read model does not declare, each with the refused method it funnels into or why it writes nothing. */
    private const array ACCOUNTED_FOR = [
        'increment'             => 'funnels into incrementOrDecrement()',
        'decrement'             => 'funnels into incrementOrDecrement()',
        'incrementQuietly'      => 'funnels into incrementOrDecrement()',
        'decrementQuietly'      => 'funnels into incrementOrDecrement()',
        'incrementEach'         => 'funnels into incrementOrDecrementEach()',
        'decrementEach'         => 'funnels into incrementOrDecrementEach()',
        'incrementEachQuietly'  => 'funnels into incrementOrDecrementEach()',
        'decrementEachQuietly'  => 'funnels into incrementOrDecrementEach()',
        'updateOrFail'          => 'fills, then funnels into saveOrFail()',
        'saveOrFail'            => 'funnels into save() inside a transaction',
        'pushQuietly'           => 'funnels into push()',
        'touchQuietly'          => 'funnels into touch()',
        'deleteOrFail'          => 'funnels into delete() inside a transaction',
        'destroy'               => 'reads the entries, then funnels into delete()',
        'forceDestroy'          => 'funnels into destroy()',
        'performInsert'         => 'called only by save()',
        'performUpdate'         => 'called only by save()',
        'performInsertOrIgnore' => 'called only by saveOrIgnore()',
        'performDeleteOnModel'  => 'called only by delete()',
        'touchOwners'           => 'touches the relations in $touches, which has none',
        'touches'               => 'a predicate, writes nothing',
        'updateTimestamps'      => 'sets attributes, writes nothing',
        'saved'                 => 'registers a listener, writes nothing',
        'created'               => 'registers a listener, writes nothing',
        'updated'               => 'registers a listener, writes nothing',
        'deleted'               => 'registers a listener, writes nothing',
    ];

    /** @var array<string, int|string|null> The seeded entry's columns, as literal stored values; JSON keys in the order MySQL keeps them (shorter first). */
    private const array ROW = [
        'id'                => self::ID,
        'record_version'    => 1,
        'event'             => 'invoice.approved',
        'event_version'     => 2,
        'category'          => 'billing',
        'outcome'           => 'success',
        'reason'            => null,
        'actor_type'        => 'user',
        'actor_id'          => '42',
        'subject_type'      => 'invoice',
        'subject_id'        => 'inv-1001',
        'principal_type'    => null,
        'principal_id'      => null,
        'tenant_type'       => 'team',
        'tenant_id'         => '7',
        'credential_id'     => null,
        'guard'             => 'web',
        'session_id'        => null,
        'request_id'        => 'req-1',
        'trace_id'          => null,
        'correlation_id'    => null,
        'origin'            => 'http',
        'provenance'        => 'captured',
        'source_id'         => 'billing-app',
        'source_region'     => null,
        'source_record_id'  => null,
        'import_batch_id'   => null,
        'ip'                => '203.0.113.7',
        'user_agent'        => 'Mozilla/5.0',
        'context'           => '{"flags":[1,2],"locale":"en-GB"}',
        'properties'        => '{"lines":3,"amount":"10.00"}',
        'occurred_at'       => '2026-11-01 12:00:00.123456',
        'recorded_at'       => '2026-11-01 12:00:00.234567',
        'integrity_version' => 1,
        'key_id'            => 'd0123456789abcdef',
        'hmac'              => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    ];

    /**
     * The entry lives in the table `entries.table` names, on the connection
     * `storage.connection` names, and in the default table on the default
     * connection when neither is set.
     *
     * @return void
     */
    public function testIsOnTheStorageConnectionInTheConfiguredTable(): void
    {
        $entry = new AuditEntry;

        self::assertSame(self::TABLE, $entry->getTable());
        self::assertNull($entry->getConnectionName());
        self::assertSame(self::CONNECTION, $entry->getConnection()->getName());

        $config = app(ConfigRepository::class);

        $config->set('database.connections.audit', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.entries.table', 'tenant_audit');
        $config->set('audit-log.storage.connection', 'audit');

        $entry = new AuditEntry;

        self::assertSame('tenant_audit', $entry->getTable());
        self::assertSame('audit', $entry->getConnectionName());
        self::assertSame('audit', $entry->getConnection()->getName());
        self::assertSame('tenant_audit', AuditEntry::query()->toBase()->from);
        self::assertSame('audit', AuditEntry::query()->getModel()->getConnectionName());
    }

    /**
     * A table setting the migration could not build its index names from fails
     * closed when an entry is constructed, rather than reading another table.
     *
     * @return void
     */
    public function testRefusesAMalformedTableSetting(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', 'audit.entries');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.');

        new AuditEntry;
    }

    /**
     * The key is the string `id`, never incremented, and the entry has neither
     * created nor updated times.
     *
     * @return void
     */
    public function testHasAStringKeyAndNoTimestamps(): void
    {
        $entry = $this->seedEntry();

        self::assertSame('id', $entry->getKeyName());
        self::assertSame('string', $entry->getKeyType());
        self::assertFalse($entry->getIncrementing());
        self::assertFalse($entry->usesTimestamps());
        self::assertSame(self::ID, $entry->getKey());
    }

    /**
     * No attribute is mass assignable, so filling one fails loudly rather than
     * being discarded.
     *
     * @return void
     */
    public function testNothingIsMassAssignable(): void
    {
        self::assertSame([], (new AuditEntry)->getFillable());
        self::assertTrue((new AuditEntry)->totallyGuarded());

        $this->expectException(MassAssignmentException::class);

        new AuditEntry(['event' => 'invoice.approved']);
    }

    /**
     * Rows of `[write through a stored entry, the method the refusal names]`:
     * every write path of the model, and the builder paths that build a model
     * to save; a path that funnels into a refused method names that method.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Models\AuditEntry): mixed, 1: string}>
     */
    public static function provideRefusedWrites(): iterable
    {
        yield from [
            'save'                 => [static fn (AuditEntry $entry): mixed => $entry->save(), 'save'],
            'saveQuietly'          => [static fn (AuditEntry $entry): mixed => $entry->saveQuietly(), 'saveQuietly'],
            'saveOrFail'           => [static fn (AuditEntry $entry): mixed => $entry->saveOrFail(), 'save'],
            'saveOrIgnore'         => [static fn (AuditEntry $entry): mixed => $entry->replicate()->saveOrIgnore(), 'saveOrIgnore'],
            'update'               => [static fn (AuditEntry $entry): mixed => $entry->update(['reason' => 'changed']), 'update'],
            'updateQuietly'        => [static fn (AuditEntry $entry): mixed => $entry->updateQuietly(['reason' => 'changed']), 'updateQuietly'],
            'updateOrFail'         => [static fn (AuditEntry $entry): mixed => $entry->updateOrFail([]), 'save'],
            'push'                 => [static fn (AuditEntry $entry): mixed => $entry->push(), 'push'],
            'pushQuietly'          => [static fn (AuditEntry $entry): mixed => $entry->pushQuietly(), 'push'],
            'touch'                => [static fn (AuditEntry $entry): mixed => $entry->touch(), 'touch'],
            'touch a column'       => [static fn (AuditEntry $entry): mixed => $entry->touch('recorded_at'), 'touch'],
            'touchQuietly'         => [static fn (AuditEntry $entry): mixed => $entry->touchQuietly(), 'touch'],
            'delete'               => [static fn (AuditEntry $entry): mixed => $entry->delete(), 'delete'],
            'deleteQuietly'        => [static fn (AuditEntry $entry): mixed => $entry->deleteQuietly(), 'deleteQuietly'],
            'deleteOrFail'         => [static fn (AuditEntry $entry): mixed => $entry->deleteOrFail(), 'delete'],
            'forceDelete'          => [static fn (AuditEntry $entry): mixed => $entry->forceDelete(), 'forceDelete'],
            'increment'            => [static fn (AuditEntry $entry): mixed => $entry->increment('record_version'), 'incrementOrDecrement'],
            'decrement'            => [static fn (AuditEntry $entry): mixed => $entry->decrement('record_version'), 'incrementOrDecrement'],
            'incrementQuietly'     => [static fn (AuditEntry $entry): mixed => $entry->incrementQuietly('record_version'), 'incrementOrDecrement'],
            'decrementQuietly'     => [static fn (AuditEntry $entry): mixed => $entry->decrementQuietly('record_version'), 'incrementOrDecrement'],
            'incrementEach'        => [static fn (AuditEntry $entry): mixed => $entry->incrementEach(['record_version' => 1]), 'incrementOrDecrementEach'],
            'decrementEach'        => [static fn (AuditEntry $entry): mixed => $entry->decrementEach(['record_version' => 1]), 'incrementOrDecrementEach'],
            'incrementEachQuietly' => [static fn (AuditEntry $entry): mixed => $entry->incrementEachQuietly(['record_version' => 1]), 'incrementOrDecrementEach'],
            'decrementEachQuietly' => [static fn (AuditEntry $entry): mixed => $entry->decrementEachQuietly(['record_version' => 1]), 'incrementOrDecrementEach'],
            'forceCreate'          => [static fn (AuditEntry $entry): mixed => AuditEntry::forceCreate(['event' => $entry->event]), 'save'],
            'forceCreateQuietly'   => [static fn (AuditEntry $entry): mixed => AuditEntry::query()->forceCreateQuietly(['event' => $entry->event]), 'save'],
            'create, unfilled'     => [static fn (AuditEntry $entry): mixed => AuditEntry::query()->create(), 'save'],
            'updateOrCreate'       => [static fn (AuditEntry $entry): mixed => AuditEntry::query()->updateOrCreate(['id' => $entry->id]), 'save'],
            'a replica saved'      => [static fn (AuditEntry $entry): mixed => $entry->replicate()->save(), 'save'],
            'destroy'              => [static fn (AuditEntry $entry): mixed => AuditEntry::destroy($entry->id), 'delete'],
            'forceDestroy'         => [static fn (AuditEntry $entry): mixed => AuditEntry::forceDestroy([$entry->id]), 'delete'],
        ];
    }

    /**
     * Each write through a stored entry is refused with the exception naming
     * the refused method it reaches.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Models\AuditEntry): mixed  $write
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideRefusedWrites')]
    public function testRefusesEveryWriteThroughTheModel(\Closure $write, string $method): void
    {
        self::skipUnlessAModelMethod($method);

        $entry = $this->seedEntry();

        $this->expectException(ImmutableEntryException::class);
        $this->expectExceptionMessage(sprintf(self::MESSAGE, $method));

        $write($entry);
    }

    /**
     * A write that fills an attribute is refused by mass assignment before it
     * reaches a refused method, so it too writes nothing: no row is added and
     * the stored one is unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMassAssignedWriteIsRefusedBeforeItWrites(): void
    {
        $entry  = $this->seedEntry();
        $stored = $this->stored();

        $writes = [
            'create'        => static fn (): mixed => AuditEntry::create(['event' => 'invoice.voided']),
            'updateOrFail'  => static fn (): mixed => $entry->updateOrFail(['event' => 'invoice.voided']),
            'firstOrCreate' => static fn (): mixed => AuditEntry::query()->firstOrCreate(['id' => self::NEW_ID]),
            'createOrFirst' => static fn (): mixed => AuditEntry::query()->createOrFirst(['id' => self::NEW_ID]),
        ];

        foreach ($writes as $name => $write) {
            try {
                $write();

                self::fail(sprintf('Expected %s() to be refused.', $name));
            } catch (MassAssignmentException) {
                // The refusal this test expects
            }
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
        self::assertSame($stored, $this->stored());
    }

    /**
     * An entry that was never stored is never saved either: saving it,
     * inserting it while ignoring conflicts, and incrementing a column on it,
     * which would otherwise update every row, are each refused, and no row is
     * added or changed.
     *
     * @return void
     */
    public function testANewEntryIsNeverSaved(): void
    {
        $this->seedEntry();

        $stored     = $this->stored();
        $attributes = [
            ...self::ROW,
            'id'          => self::NEW_ID,
            'context'     => ['locale' => 'en-GB'],
            'properties'  => [],
            'occurred_at' => CarbonImmutable::parse('2026-11-01T13:00:00.000001Z'),
            'recorded_at' => CarbonImmutable::parse('2026-11-01T13:00:00.000002Z'),
        ];

        self::assertRefuses('save', static fn (): mixed => (new AuditEntry)->forceFill($attributes)->save());
        self::assertRefuses('saveOrIgnore', static fn (): mixed => (new AuditEntry)->forceFill($attributes)->saveOrIgnore());
        self::assertRefuses('saveOrIgnore', static fn (): mixed => (new AuditEntry)->saveOrIgnore());
        self::assertRefuses('incrementOrDecrement', static fn (): mixed => (new AuditEntry)->increment('record_version'));
        self::assertRefuses('incrementOrDecrement', static fn (): mixed => (new AuditEntry)->decrement('event_version', 1, ['reason' => 'changed']));

        if (self::isAModelMethod('incrementOrDecrementEach')) {
            self::assertRefuses('incrementOrDecrementEach', static fn (): mixed => (new AuditEntry)->incrementEach(['record_version' => 1]));
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
        self::assertSame($stored, $this->stored());
    }

    /**
     * Every method of the installed model whose name says it may write is
     * either declared on the read model or accounted for as funnelling into one
     * that is, or as writing nothing, so a Laravel release that adds a write
     * path fails here; and the read model declares exactly the refused methods,
     * its constructor and its casts.
     *
     * @return void
     */
    public function testEveryModelWritePathIsAccountedFor(): void
    {
        $unaccounted = [];

        foreach ((new \ReflectionClass(Model::class))->getMethods(\ReflectionMethod::IS_PUBLIC | \ReflectionMethod::IS_PROTECTED) as $method) {
            if (preg_match(self::WRITE_METHOD, $method->getName()) !== 1 || array_key_exists($method->getName(), self::ACCOUNTED_FOR)) {
                continue;
            }

            if ((new \ReflectionMethod(AuditEntry::class, $method->getName()))->getDeclaringClass()->getName() === AuditEntry::class) {
                continue;
            }

            $unaccounted[] = $method->getName();
        }

        self::assertSame([], $unaccounted, 'A model write method is neither refused nor accounted for.');

        $declared = array_values(array_map(
            static fn (\ReflectionMethod $method): string => $method->getName(),
            array_filter(
                (new \ReflectionClass(AuditEntry::class))->getMethods(),
                static fn (\ReflectionMethod $method): bool => $method->getDeclaringClass()->getName() === AuditEntry::class,
            ),
        ));

        sort($declared);

        self::assertSame([
            '__construct', 'casts', 'delete', 'deleteQuietly', 'forceDelete', 'incrementOrDecrement', 'incrementOrDecrementEach',
            'push', 'refuse', 'save', 'saveOrIgnore', 'saveQuietly', 'touch', 'update', 'updateQuietly',
        ], $declared);
        self::assertSame([], array_intersect(array_keys(self::ACCOUNTED_FOR), $declared));
    }

    /**
     * Across every refused write, no insert, update or delete statement runs,
     * the table keeps its one row, and the row is unchanged.
     *
     * @return void
     */
    public function testARefusedWriteLeavesTheRowAndIssuesNoWrite(): void
    {
        $this->seedEntry();

        $stored     = $this->stored();
        $connection = DB::connection();

        foreach (self::provideRefusedWrites() as $name => [$write, $method]) {
            if (!self::isAModelMethod($method)) {
                continue;
            }

            $entry = AuditEntry::query()->findOrFail(self::ID);

            $connection->flushQueryLog();
            $connection->enableQueryLog();

            self::assertRefuses($method, static fn (): mixed => $write($entry));

            $writes = array_filter($connection->getQueryLog(), static fn (array $query): bool => preg_match(self::WRITE_STATEMENT, $query['query']) === 1);

            $connection->disableQueryLog();

            self::assertSame([], $writes, sprintf('%s issued a write.', $name));
            self::assertSame(1, DB::table(self::TABLE)->count(), sprintf('%s added a row.', $name));
            self::assertSame($stored, $this->stored(), sprintf('%s changed the row.', $name));
        }
    }

    /**
     * A refused write is refused before any model event fires, so no listener
     * sees an entry about to be saved, updated, created or deleted.
     *
     * @return void
     */
    public function testARefusedWriteFiresNoModelEvent(): void
    {
        $this->seedEntry();

        $fired = [];

        foreach (['saving', 'saved', 'creating', 'created', 'updating', 'updated', 'deleting', 'deleted'] as $event) {
            Event::listen('eloquent.' . $event . ': ' . AuditEntry::class, static function () use (&$fired, $event): void {
                $fired[] = $event;
            });
        }

        foreach (self::provideRefusedWrites() as [$write, $method]) {
            if (!self::isAModelMethod($method)) {
                continue;
            }

            $entry = AuditEntry::query()->findOrFail(self::ID);

            self::assertRefuses($method, static fn (): mixed => $write($entry));
        }

        self::assertSame([], $fired);
    }

    /**
     * Query-builder writes bypass the model, as documented: an update and a
     * delete through the builder change and remove the row, which is why
     * append-only access rests on the database's grants, and how pruning will
     * delete.
     *
     * @return void
     */
    public function testQueryBuilderWritesBypassTheModelAsDocumented(): void
    {
        $this->seedEntry();

        self::assertSame(1, AuditEntry::query()->whereKey(self::ID)->update(['reason' => 'changed']));
        self::assertSame('changed', DB::table(self::TABLE)->value('reason'));

        self::assertSame(1, AuditEntry::query()->whereKey(self::ID)->delete());
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * The versions read as integers, the JSON columns as arrays and the times
     * as UTC instants with their microseconds; every other column reads as it
     * is stored.
     *
     * @return void
     */
    public function testCastsTheColumnsItReads(): void
    {
        $entry = $this->seedEntry();

        self::assertSame([
            'record_version'    => 'integer',
            'event_version'     => 'integer',
            'context'           => 'array',
            'properties'        => 'array',
            'occurred_at'       => UtcInstant::class,
            'recorded_at'       => UtcInstant::class,
            'integrity_version' => 'integer',
        ], $entry->getCasts());

        self::assertSame(1, $entry->record_version);
        self::assertSame(2, $entry->event_version);
        self::assertSame(1, $entry->integrity_version);
        self::assertSame(['flags' => [1, 2], 'locale' => 'en-GB'], $entry->context);
        self::assertSame(['lines' => 3, 'amount' => '10.00'], $entry->properties);
        self::assertInstanceOf(CarbonImmutable::class, $entry->occurred_at);
        self::assertSame('UTC', $entry->occurred_at->getTimezone()->getName());
        self::assertSame('2026-11-01T12:00:00.123456Z', $entry->occurred_at->format('Y-m-d\TH:i:s.u\Z'));
        self::assertSame('2026-11-01T12:00:00.234567Z', $entry->recorded_at->format('Y-m-d\TH:i:s.u\Z'));
        self::assertSame('invoice.approved', $entry->event);
        self::assertSame('captured', $entry->provenance);
        self::assertNull($entry->reason);
    }

    /**
     * Serialising an entry gives its times in the package's form, ISO-8601 UTC
     * with microseconds, the form the record they came from had.
     *
     * @return void
     */
    public function testSerialisesItsTimesInThePackagesForm(): void
    {
        $array = $this->seedEntry()->toArray();

        self::assertSame('2026-11-01T12:00:00.123456Z', $array['occurred_at']);
        self::assertSame('2026-11-01T12:00:00.234567Z', $array['recorded_at']);
    }

    /**
     * The model declares no query scope, local or global: reads go through the
     * trail.
     *
     * @return void
     */
    public function testHasNoQueryScopes(): void
    {
        foreach ((new \ReflectionClass(AuditEntry::class))->getMethods() as $method) {
            self::assertDoesNotMatchRegularExpression('/\Ascope[A-Z]/', $method->getName());
            self::assertSame([], $method->getAttributes(Scope::class), $method->getName());
        }

        self::assertSame([], (new AuditEntry)->getGlobalScopes());
    }

    /**
     * Insert the entry's row with a literal statement and read it back through
     * the model.
     *
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function seedEntry(): AuditEntry
    {
        DB::table(self::TABLE)->insert(self::ROW);

        return AuditEntry::query()->findOrFail(self::ID);
    }

    /**
     * The entry's row as the database returns it.
     *
     * @return array<string, scalar|null>
     */
    private function stored(): array
    {
        /** @var array<string, scalar|null> */
        return (array) DB::table(self::TABLE)->where('id', self::ID)->first();
    }

    /**
     * Assert the write is refused with the exception naming the method.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $method
     * @param  \Closure(): mixed  $write
     * @return void
     */
    private static function assertRefuses(string $method, \Closure $write): void
    {
        try {
            $write();

            self::fail(sprintf('Expected %s() to be refused.', $method));
        } catch (ImmutableEntryException $exception) {
            self::assertSame(sprintf(self::MESSAGE, $method), $exception->getMessage());
        }
    }

    /**
     * Whether the refused method is a write path of the installed model: on
     * Laravel 12, `incrementEach()` and its kin are builder writes, not model
     * methods.
     *
     * @param  string  $method
     * @return bool
     */
    private static function isAModelMethod(string $method): bool
    {
        return $method !== 'incrementOrDecrementEach' || (new \ReflectionClass(Model::class))->hasMethod($method);
    }

    /**
     * Skip a row whose method the installed model lacks.
     *
     * @param  string  $method
     * @return void
     */
    private static function skipUnlessAModelMethod(string $method): void
    {
        if (self::isAModelMethod($method)) {
            return;
        }

        self::markTestSkipped('On Laravel 12, `incrementEach()` on an entry is a query-builder write, not a model method.');
    }
}
