<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Rfc4122\FieldsInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\RecordVersion;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for the captured record: its shape and its one named constructor,
 * the pinned envelope and the golden v1 record, the UUID version 7 id and its
 * order, the UTC instant, the versions, provenance and source it carries, the
 * reference pairs, where a note is stored and that an owned note never is, and
 * the refusals of building one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRecord::class)]
final class AuditRecordTest extends TestCase
{
    /** @var string The id the golden record is built with. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The golden v1 envelope. */
    private const string FIXTURE = __DIR__ . '/../../Fixtures/Records/audit-record-v1.json';

    /** @var list<string> The envelope's keys, in order. */
    private const array KEYS = [
        'id', 'record_version', 'event', 'event_version', 'category', 'outcome', 'reason', 'actor_type', 'actor_id',
        'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_type', 'tenant_id', 'credential_id',
        'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id', 'origin', 'provenance', 'source_id',
        'source_region', 'source_record_id', 'import_batch_id', 'ip', 'user_agent', 'context', 'properties',
        'occurred_at',
    ];

    /**
     * Raise every PHP warning as an exception, so each record is also built
     * quietly: inside a Laravel application a warning becomes an exception,
     * which would turn recording an activity into an error.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });
    }

    /**
     * Restore the error handler and UUID generation after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        restore_error_handler();

        Str::createUuidsNormally();

        parent::tearDown();
    }

    /**
     * The record is final and readonly, its constructor is private, and its
     * only public methods are `fromPending()`, the one that returns a record,
     * and `toArray()`.
     *
     * @return void
     */
    public function testIsFinalAndReadonlyWithOnlyOneNamedConstructor(): void
    {
        $reflection  = new \ReflectionClass(AuditRecord::class);
        $constructor = $reflection->getConstructor();

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $methods = array_map(static fn (\ReflectionMethod $method): string => $method->getName(), $reflection->getMethods(\ReflectionMethod::IS_PUBLIC));
        $static  = array_filter($reflection->getMethods(\ReflectionMethod::IS_STATIC), static fn (\ReflectionMethod $method): bool => $method->isPublic());

        self::assertSame(['fromPending', 'toArray'], $methods);
        self::assertSame(['fromPending'], array_values(array_map(static fn (\ReflectionMethod $method): string => $method->getName(), $static)));
        self::assertSame('self', (string) $reflection->getMethod('fromPending')->getReturnType());
    }

    /**
     * Every leaf of the envelope is a string, an integer, a boolean or `null`,
     * even when the properties were given a model, an enum and a date: the
     * record holds no object, enums included.
     *
     * @return void
     */
    public function testEveryLeafOfTheEnvelopeIsAScalarOrNull(): void
    {
        $pending = self::fullBuilder()->withProperties([
            'approver' => (new StubUser)->forceFill(['id' => 9]),
            'colour'   => StubColour::RED,
            'due'      => new \DateTimeImmutable('2026-12-01 09:00:00', new \DateTimeZone('UTC')),
            'ratio'    => 0.5,
        ]);

        $envelope = self::build($pending)->toArray();
        $leaves   = [];

        array_walk_recursive($envelope, static function (mixed $leaf) use (&$leaves): void {
            $leaves[] = $leaf;
        });

        self::assertNotEmpty($leaves);

        foreach ($leaves as $leaf) {
            self::assertTrue($leaf === null || is_string($leaf) || is_int($leaf) || is_bool($leaf), 'A leaf of type ' . get_debug_type($leaf) . ' is not a scalar.');
        }
    }

    /**
     * The envelope has exactly the 32 keys of the entries table, without the
     * finalisation columns, in that order.
     *
     * @return void
     */
    public function testTheEnvelopeKeysArePinned(): void
    {
        self::assertSame(self::KEYS, array_keys(self::build(self::fullBuilder())->toArray()));
        self::assertSame(self::KEYS, array_keys(self::build(self::minimalBuilder())->toArray()));
    }

    /**
     * The golden v1 record, decoded, is exactly the full builder's envelope,
     * and its record version is one this release reads; encoded the same way,
     * the envelope is the fixture byte for byte.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenV1RecordDecodesUnchanged(): void
    {
        $fixture = (string) file_get_contents(self::FIXTURE);
        $golden  = json_decode($fixture, true, 512, JSON_THROW_ON_ERROR);
        $record  = self::build(self::fullBuilder())->toArray();

        self::assertIsArray($golden);
        self::assertSame($golden, $record);
        self::assertIsInt($golden['record_version']);
        self::assertSame(1, RecordVersion::check($golden['record_version']));
        self::assertSame($fixture, json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n");
    }

    /**
     * With real UUIDs the id is a UUID version 7 whose leading 48 bits are the
     * instant the activity happened, in Unix milliseconds.
     *
     * @return void
     */
    public function testTheIdIsAUuidVersion7(): void
    {
        Str::createUuidsNormally();

        $id     = self::build(self::minimalBuilder())->id;
        $fields = Uuid::fromString($id)->getFields();

        self::assertInstanceOf(FieldsInterface::class, $fields);
        self::assertSame(7, $fields->getVersion());
        self::assertSame((int) self::instant()->format('Uv'), hexdec(substr(str_replace('-', '', $id), 0, 12)));
    }

    /**
     * Fifty records captured at one frozen instant have distinct ids that sort,
     * as strings, in the order they were captured.
     *
     * @return void
     */
    public function testRecordsCapturedInOneMillisecondSortInCaptureOrder(): void
    {
        Str::createUuidsNormally();

        $ids = [];

        for ($i = 0; $i < 50; $i++) {
            $ids[] = self::build(self::minimalBuilder())->id;
        }

        $sorted = $ids;
        sort($sorted, SORT_STRING);

        self::assertSame($ids, $sorted);
        self::assertCount(50, array_unique($ids));
    }

    /**
     * An instant in any time zone is stored as the same instant in UTC, with
     * its microseconds.
     *
     * @return void
     */
    public function testOccurredAtIsUtcWithMicroseconds(): void
    {
        $auckland = new \DateTimeImmutable('2026-11-01 12:34:56.789012', new \DateTimeZone('Pacific/Auckland'));
        $carbon   = CarbonImmutable::parse('2026-06-01 08:00:00.000001', 'America/New_York');

        self::assertSame('2026-10-31T23:34:56.789012Z', self::build(self::minimalBuilder(), $auckland)->occurredAt);
        self::assertSame('2026-06-01T12:00:00.000001Z', self::build(self::minimalBuilder(), $carbon)->occurredAt);
        self::assertSame('Pacific/Auckland', $auckland->getTimezone()->getName());
    }

    /**
     * Every captured record carries the current record version.
     *
     * @return void
     */
    public function testTheRecordVersionIsTheCurrentOne(): void
    {
        self::assertSame(RecordVersion::CURRENT, self::build(self::minimalBuilder())->recordVersion);
    }

    /**
     * The event version and category are the ones the recorder gives, from the
     * code's definition.
     *
     * @return void
     */
    public function testTheEventVersionAndCategoryAreTheCallers(): void
    {
        $record = AuditRecord::fromPending(self::minimalBuilder(), 7, 'finance', self::instant(), 'app-eu-1');

        self::assertSame(7, $record->eventVersion);
        self::assertSame('finance', $record->category);
        self::assertSame('invoice.approved', $record->event);
    }

    /**
     * A captured record's provenance is `captured`, and the fields only an
     * import sets are `null`.
     *
     * @return void
     */
    public function testProvenanceIsCapturedAndTheImportFieldsAreNull(): void
    {
        $record = self::build(self::fullBuilder());

        self::assertSame('captured', $record->provenance);
        self::assertNull($record->sourceRecordId);
        self::assertNull($record->importBatchId);
    }

    /**
     * The full builder sets every reference pair, both halves; a minimal one
     * leaves every pair `null`, never an empty string.
     *
     * @return void
     */
    public function testReferencesArePairsOrAbsent(): void
    {
        $full    = self::build(self::fullBuilder());
        $minimal = self::build(self::minimalBuilder());

        self::assertSame(['user', '42', 'invoice', 'inv_0042', 'team', '7', 'organisation', 'org_01'], [
            $full->actorType, $full->actorId, $full->subjectType, $full->subjectId,
            $full->principalType, $full->principalId, $full->tenantType, $full->tenantId,
        ]);

        self::assertSame(array_fill(0, 8, null), [
            $minimal->actorType, $minimal->actorId, $minimal->subjectType, $minimal->subjectId,
            $minimal->principalType, $minimal->principalId, $minimal->tenantType, $minimal->tenantId,
        ]);
    }

    /**
     * A minimal record has the default outcome, no reason and none of the
     * optional fields.
     *
     * @return void
     */
    public function testAMinimalRecordHasOnlyItsRequiredFields(): void
    {
        $record = self::build(self::minimalBuilder())->toArray();

        self::assertSame('success', $record['outcome']);
        self::assertSame('console', $record['origin']);

        foreach (['reason', 'credential_id', 'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id', 'ip', 'user_agent', 'context', 'properties'] as $key) {
            self::assertNull($record[$key], "{$key} is set on a minimal record.");
        }
    }

    /**
     * A note without an owner is stored at `properties._audit.note`, after the
     * caller's keys; a note alone gives properties holding only the metadata.
     *
     * @return void
     */
    public function testTheNoteIsStoredUnderTheReservedMetadata(): void
    {
        $withProperties = self::build(self::minimalBuilder()->withProperties(['b' => 1, 'a' => 2])->withNote('Checked by hand'));
        $alone          = self::build(self::minimalBuilder()->withNote('Checked by hand'));

        self::assertSame(['b' => 1, 'a' => 2, '_audit' => ['note' => 'Checked by hand']], $withProperties->properties);
        self::assertSame(['_audit' => ['note' => 'Checked by hand']], $alone->properties);
    }

    /**
     * Rows of `[owner]`: every kind of owner a note can have.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference)}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideNoteOwners(): iterable
    {
        yield from [
            'a model'     => [static fn (): Model => (new StubUser)->forceFill(['id' => 3])],
            'a reference' => [static fn (): Reference => Reference::of('user', '3')],
            'the actor'   => [static fn (): KeyOwner => KeyOwner::ACTOR],
            'the subject' => [static fn (): KeyOwner => KeyOwner::SUBJECT],
        ];
    }

    /**
     * A note with an owner is never stored in plaintext: the properties hold no
     * metadata, the note's text appears nowhere in the encoded envelope, and
     * with no other properties the properties are `null`.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference)  $owner
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideNoteOwners')]
    public function testAnOwnedNoteIsNeverStoredInPlaintext(\Closure $owner): void
    {
        $withProperties = self::build(self::minimalBuilder()->withProperties(['amount' => '1200.00'])->withNote('Erasable remark', $owner()));
        $alone          = self::build(self::minimalBuilder()->withNote('Erasable remark', $owner()));

        self::assertSame(['amount' => '1200.00'], $withProperties->properties);
        self::assertNull($alone->properties);
        self::assertStringNotContainsString('Erasable remark', json_encode($withProperties->toArray(), JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('Erasable remark', json_encode($alone->toArray(), JSON_THROW_ON_ERROR));
    }

    /**
     * An owned note stays owned when a later note is refused, for its owner or
     * for its text, so the record still holds no plaintext of it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARefusedNoteLeavesAnOwnedNoteUnstored(): void
    {
        $pending = self::minimalBuilder()->withNote('Erasable remark', KeyOwner::SUBJECT);

        foreach ([static fn (): PendingRecord => $pending->withNote('Refused', new StubUser), static fn (): PendingRecord => $pending->withNote('', null)] as $refused) {
            try {
                $refused();
                self::fail('Expected the note to be refused.');
            } catch (\InvalidArgumentException) {
                // Refused as expected; the record must still not hold the note
            }
        }

        $record = self::build($pending);

        self::assertNull($record->properties);
        self::assertStringNotContainsString('Erasable remark', json_encode($record->toArray(), JSON_THROW_ON_ERROR));
    }

    /**
     * Without properties or a note the properties are `null`.
     *
     * @return void
     */
    public function testWithoutPropertiesOrANoteThePropertiesAreNull(): void
    {
        self::assertNull(self::build(self::minimalBuilder())->properties);
        self::assertNull(self::build(self::minimalBuilder()->withProperties([]))->properties);
    }

    /**
     * Without context the context is `null`; with it, it is the normalised map.
     *
     * @return void
     */
    public function testWithoutContextTheContextIsNull(): void
    {
        $pending = self::minimalBuilder();
        $pending->fillContext(['command' => 'invoices:approve']);

        self::assertNull(self::build(self::minimalBuilder())->context);
        self::assertSame(['command' => 'invoices:approve'], self::build($pending)->context);
    }

    /**
     * Building a record uses the builder up: a second build of one builder is
     * the reuse refusal.
     *
     * @return void
     */
    public function testBuildingConsumesTheBuilder(): void
    {
        $pending = self::minimalBuilder();

        self::build($pending);

        self::assertTrue($pending->isConsumed());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record is recorded once, and this one has already been recorded.');

        self::build($pending);
    }

    /**
     * A builder whose origin was never filled cannot be built into a captured
     * record.
     *
     * @return void
     */
    public function testABuilderWithoutAnOriginIsALogicError(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A captured record needs an origin; the origin contributor fills it before the record is built.');

        self::build((new PendingRecord)->event('invoice.approved'));
    }

    /**
     * A builder with no event code cannot be built, whatever else it holds.
     *
     * @return void
     */
    public function testABuilderWithoutACodeIsALogicError(): void
    {
        $pending = new PendingRecord;
        $pending->fillOrigin(Origin::HTTP);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record needs an event code before it is recorded; set one with `event()`.');

        self::build($pending);
    }

    /**
     * The longest source id is the `source_id` column's 64 characters, and the
     * longest source region the `source_region` column's 32.
     *
     * @return void
     */
    public function testTheSourceLimitsAreTheirColumns(): void
    {
        self::assertSame(64, AuditRecord::SOURCE_ID_MAX_CHARACTERS);
        self::assertSame(32, AuditRecord::SOURCE_REGION_MAX_CHARACTERS);
    }

    /**
     * Rows of `[source id, source region, message]`: ids and regions that are
     * empty, longer than their columns, or not clean.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: string}>
     */
    public static function provideRefusedSources(): iterable
    {
        $id     = 'A source id must be from 1 to 64 characters, with no control characters.';
        $region = 'A source region must be from 1 to 32 characters, with no control characters.';

        yield from [
            'an empty id'                => ['', null, $id],
            'a 65-character id'          => [str_repeat('a', 65), null, $id],
            'a line feed in the id'      => ["app\n", null, $id],
            'an empty region'            => ['app-eu-1', '', $region],
            'a 33-character region'      => ['app-eu-1', str_repeat('a', 33), $region],
            'a NUL in the region'        => ['app-eu-1', "eu\0", $region],
            'both refused, the id first' => ['', '', $id],
        ];
    }

    /**
     * Each refused source id or region fails, naming its column's limit.
     *
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedSources')]
    public function testRefusesAnInvalidSource(string $sourceId, ?string $sourceRegion, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        AuditRecord::fromPending(self::minimalBuilder(), 1, 'general', self::instant(), $sourceId, $sourceRegion);
    }

    /**
     * The source id is kept, with the region when one is given and `null` when
     * not; an id and a region exactly as long as their columns, counted in
     * characters, are kept (protects against an off-by-one mutation of either
     * cap).
     *
     * @return void
     */
    public function testTheSourceIsKept(): void
    {
        $withRegion    = AuditRecord::fromPending(self::minimalBuilder(), 1, 'general', self::instant(), 'app-eu-1', 'eu-west-2');
        $withoutRegion = AuditRecord::fromPending(self::minimalBuilder(), 1, 'general', self::instant(), 'app-eu-1');
        $longest       = AuditRecord::fromPending(self::minimalBuilder(), 1, 'general', self::instant(), str_repeat('é', 64), str_repeat('é', 32));

        self::assertSame(['app-eu-1', 'eu-west-2'], [$withRegion->sourceId, $withRegion->sourceRegion]);
        self::assertSame(['app-eu-1', null], [$withoutRegion->sourceId, $withoutRegion->sourceRegion]);
        self::assertSame([str_repeat('é', 64), str_repeat('é', 32)], [$longest->sourceId, $longest->sourceRegion]);
    }

    /**
     * The credential id is marked sensitive on the constructor, so it never
     * appears in a stack trace.
     *
     * @return void
     */
    public function testTheCredentialIdIsMarkedSensitive(): void
    {
        $constructor = (new \ReflectionClass(AuditRecord::class))->getConstructor();

        self::assertNotNull($constructor);

        $parameters = array_filter($constructor->getParameters(), static fn (\ReflectionParameter $parameter): bool => $parameter->getName() === 'credentialId');

        self::assertCount(1, $parameters);
        self::assertCount(1, array_values($parameters)[0]->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The golden record's builder: every field set, under a fixed id.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function fullBuilder(): PendingRecord
    {
        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString(self::ID));

        $pending = (new PendingRecord)
            ->event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', 42))
            ->asPrincipal(Reference::of('team', '7'))
            ->forTenant(Reference::of('organisation', 'org_01'))
            ->usingCredential('key_01')
            ->correlatedWith('app:ticket-123')
            ->withProperties(['amount' => '1200.00', 'currency' => 'GBP', 'lines' => [1, 2]])
            ->withNote('Approved after review')
            ->denied('policy')
            ->transactional('business')
            ->failClosed();

        $pending->fillGuard('web');
        $pending->fillSession('sess_ref_1');
        $pending->fillRequest('01932b4e-8a40-7000-8000-0000000000aa', '4bf92f3577b34da6a3ce929d0e0e4736');
        $pending->fillClient('203.0.113.7', 'Mozilla/5.0');
        $pending->fillOrigin(Origin::HTTP);
        $pending->fillContext(['route' => 'invoices.approve', 'method' => 'POST']);

        return $pending;
    }

    /**
     * A builder with only what a captured record needs: a code and an origin.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function minimalBuilder(): PendingRecord
    {
        $pending = (new PendingRecord)->event('invoice.approved');
        $pending->fillOrigin(Origin::CONSOLE);

        return $pending;
    }

    /**
     * The captured record of the builder, as the golden record is built.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\DateTimeInterface  $occurredAt
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function build(PendingRecord $pending, ?\DateTimeInterface $occurredAt = null): AuditRecord
    {
        return AuditRecord::fromPending($pending, 2, 'finance', $occurredAt ?? self::instant(), 'app-eu-1', 'eu-west-2');
    }

    /**
     * The golden record's instant: noon and a little in Auckland, in summer
     * time, which is the evening before in UTC.
     *
     * @return \DateTimeImmutable
     */
    private static function instant(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2026-11-01 12:34:56.789012', new \DateTimeZone('Pacific/Auckland'));
    }
}
