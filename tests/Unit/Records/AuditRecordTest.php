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
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\RecordVersion;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for the captured record: its shape and its three named
 * constructors, the pinned envelope and the golden v1 record, the UUID version
 * 7 id and its order, the UTC instant, the versions, provenance and source it
 * carries, the reference pairs, that it stores only what minimising left, where
 * a note is stored and that an owned note never is, and the refusals of
 * building one; an imported record, its source fields, its id drawn at import,
 * its kept occurrence time, its optional origin and its refusals; and a record
 * rebuilt from an envelope, every field kept as given, and the envelopes it
 * refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRecord::class)]
final class AuditRecordTest extends TestCase
{
    /** @var string The refusal of a record built with an attachment that is not its manifest's. */
    private const string UNBOUND = 'A record with an artifact is built with the attachment of its own manifest, and any other record with none.';

    /** @var string The refusal of an envelope and an attachment that do not describe one artifact. */
    private const string MISMATCHED = 'A record\'s manifest and its attachment must describe the same artifact.';

    /** @var string The id the golden record is built with. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The golden v1 envelope. */
    private const string FIXTURE = __DIR__ . '/../../Fixtures/Records/audit-record-v1.json';

    /** @var list<string> The envelope's keys, in order. */
    private const array KEYS = [
        'id', 'record_version', 'event', 'event_version', 'category', 'outcome', 'reason', 'actor_type', 'actor_id',
        'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_type', 'tenant_id', 'credential_id',
        'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id', 'origin', 'provenance', 'source_id',
        'source_region', 'source_record_id', 'import_batch_id', 'source_digest', 'ip', 'user_agent', 'context',
        'properties', 'occurred_at',
    ];

    /** @var string The refusal of an imported record with an artifact. */
    private const string NO_ARTIFACT = 'An imported record carries no artifact.';

    /** @var string When the imported records are imported: two days after the golden record's activity. */
    private const string IMPORTED_AT = '2026-11-02T08:15:30.250000Z';

    /** @var string When an imported record's activity happened, as its source gave it. */
    private const string SOURCE_OCCURRED_AT = '2019-03-04T05:06:07.080910Z';

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
     * only public methods are `fromPending()`, the one named constructor that
     * captures a record, `fromImport()`, the one that imports one,
     * `fromEnvelope()`, which only the codec calls to rebuild one, and
     * `toArray()`.
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

        self::assertSame(['fromEnvelope', 'fromPending', 'fromImport', 'toArray'], $methods);
        self::assertSame(['fromEnvelope', 'fromPending', 'fromImport'], array_values(array_map(static fn (\ReflectionMethod $method): string => $method->getName(), $static)));
        // PHP 8.5 reports a `self` return type by the class it names.
        self::assertContains((string) $reflection->getMethod('fromPending')->getReturnType(), ['self', AuditRecord::class]);
        self::assertContains((string) $reflection->getMethod('fromImport')->getReturnType(), ['self', AuditRecord::class]);
        self::assertContains((string) $reflection->getMethod('fromEnvelope')->getReturnType(), ['self', AuditRecord::class]);
    }

    /**
     * A record rebuilt from an envelope keeps every field as given, in the
     * envelope's order, whatever capture would have made of it: an id that is
     * not a version 7 UUID, upper-case and unclean text, a list as the
     * properties, and a version the release does not read.
     *
     * @return void
     */
    public function testAnEnvelopeKeepsEveryField(): void
    {
        $fields = array_replace(self::build(self::fullBuilder())->toArray(), [
            'id'             => '6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b',
            'record_version' => 9,
            'event'          => 'Invoice.Approved',
            'user_agent'     => "Agent\0\u{202E}",
            'ip'             => '203.0.113.7',
            'context'        => [],
            'properties'     => ['password' => 'hunter2', 'lines' => ['b', 'a']],
            'occurred_at'    => '2020-01-01T00:00:00.000001Z',
        ]);

        self::assertSame($fields, AuditRecord::fromEnvelope($fields)->toArray());
        self::assertSame($fields, AuditRecord::fromEnvelope([...$fields, 'recorded_at' => '2026-11-01T12:00:00.000000Z', 'hmac' => 'ignored'])->toArray());
    }

    /**
     * A record rebuilt from an envelope keeps its provenance and import fields
     * as given: an imported record stays imported, with its source record, its
     * batch and its source digest.
     *
     * @return void
     */
    public function testAnEnvelopeKeepsItsProvenance(): void
    {
        $fields = array_replace(self::build(self::minimalBuilder())->toArray(), [
            'provenance'       => 'imported',
            'source_id'        => 'legacy-app',
            'source_region'    => null,
            'source_record_id' => 'legacy-0042',
            'import_batch_id'  => '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e',
            'source_digest'    => str_repeat('ab', 32),
            'origin'           => null,
        ]);

        $record = AuditRecord::fromEnvelope($fields);

        self::assertSame('imported', $record->provenance);
        self::assertSame(['legacy-app', null, 'legacy-0042', '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e', str_repeat('ab', 32), null], [
            $record->sourceId, $record->sourceRegion, $record->sourceRecordId, $record->importBatchId, $record->sourceDigest, $record->origin,
        ]);
        self::assertSame($fields, $record->toArray());
    }

    /**
     * Rows of `[field, value, message]`: a field of another type for each kind
     * of field, and a field missing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideRefusedEnvelopes(): iterable
    {
        yield from [
            'a string field holding null'       => ['event', null, 'An envelope\'s `event` must be a string.'],
            'a string field holding an integer' => ['occurred_at', 1, 'An envelope\'s `occurred_at` must be a string.'],
            'a nullable field holding an int'   => ['reason', 1, 'An envelope\'s `reason` must be a string or null.'],
            'a nullable field holding a list'   => ['actor_id', ['42'], 'An envelope\'s `actor_id` must be a string or null.'],
            'a source digest holding an int'    => ['source_digest', 1, 'An envelope\'s `source_digest` must be a string or null.'],
            'an integer field holding a string' => ['record_version', '1', 'An envelope\'s `record_version` must be an integer.'],
            'an integer field holding null'     => ['event_version', null, 'An envelope\'s `event_version` must be an integer.'],
            'an array field holding a string'   => ['context', '{}', 'An envelope\'s `context` must be an array or null.'],
            'an array field holding an object'  => ['properties', new \stdClass, 'An envelope\'s `properties` must be an array or null.'],
        ];
    }

    /**
     * A field of another type is refused, naming the field and what it must be,
     * never the value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $field
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedEnvelopes')]
    public function testAnEnvelopeOfAnotherTypeIsRefused(string $field, mixed $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        AuditRecord::fromEnvelope([$field => $value] + self::build(self::minimalBuilder())->toArray());
    }

    /**
     * An envelope without a field is refused, naming the field, even one that
     * may hold `null`: a missing field is never read as `null`.
     *
     * @return void
     */
    public function testAnEnvelopeWithoutAFieldIsRefused(): void
    {
        foreach (self::KEYS as $key) {
            $fields = self::build(self::minimalBuilder())->toArray();

            unset($fields[$key]);

            try {
                AuditRecord::fromEnvelope($fields);
                self::fail("Expected an envelope without `{$key}` to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("An envelope has no `{$key}` field.", $exception->getMessage());
            }
        }
    }

    /**
     * The envelope's parameter is marked sensitive: it holds the record's
     * values, and a refusal is thrown with it on the stack.
     *
     * @return void
     */
    public function testTheEnvelopeParameterIsSensitive(): void
    {
        $parameter = (new \ReflectionMethod(AuditRecord::class, 'fromEnvelope'))->getParameters()[0];

        self::assertSame('fields', $parameter->getName());
        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
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
     * The envelope has exactly the 33 keys of the entries table, without the
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
        $pending = self::minimalBuilder();
        $record  = AuditRecord::fromPending($pending, RecordFactory::minimisedOf($pending), 7, 'finance', self::instant(), 'app-eu-1');

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
     * A captured record has no source digest, in its envelope as on the record:
     * only an import computes one.
     *
     * @return void
     */
    public function testACapturedRecordHasNoSourceDigest(): void
    {
        foreach ([self::build(self::fullBuilder()), self::build(self::minimalBuilder())] as $record) {
            self::assertNull($record->sourceDigest);
            self::assertArrayHasKey('source_digest', $record->toArray());
            self::assertNull($record->toArray()['source_digest']);
        }
    }

    /**
     * An imported record is `imported`, with the current record version, the
     * event version and category given, the references, outcome, reason,
     * correlation id, IP, context and properties of its builder, and every
     * source field of its source: the source that asserted it, its region, the
     * record's id there, the batch and the digest.
     *
     * @return void
     */
    public function testFromImportIsImportedWithItsSourceFields(): void
    {
        $pending = self::importBuilder();
        $source  = RecordFactory::source('legacy-0042', str_repeat('c0', 32));
        $record  = AuditRecord::fromImport($pending, RecordFactory::minimisedOf($pending), 3, 'finance', self::SOURCE_OCCURRED_AT, 'queue', $source, self::importedAt());

        self::assertSame('imported', $record->provenance);
        self::assertSame(RecordVersion::CURRENT, $record->recordVersion);
        self::assertSame(['invoice.approved', 3, 'finance', 'denied', 'policy'], [$record->event, $record->eventVersion, $record->category, $record->outcome, $record->reason]);
        self::assertSame(['user', '42', 'invoice', 'inv_0042', 'team', '7', 'organisation', 'org_01'], [
            $record->actorType, $record->actorId, $record->subjectType, $record->subjectId,
            $record->principalType, $record->principalId, $record->tenantType, $record->tenantId,
        ]);
        self::assertSame(['legacy:ticket-7', 'queue', '198.51.100.4'], [$record->correlationId, $record->origin, $record->ip]);
        self::assertSame(['route' => 'invoices.approve'], $record->context);
        self::assertSame(['amount' => '1200.00'], $record->properties);
        self::assertSame(['legacy-app', 'eu-west-1', 'legacy-0042', RecordFactory::IMPORT_BATCH_ID, str_repeat('c0', 32)], [
            $record->sourceId, $record->sourceRegion, $record->sourceRecordId, $record->importBatchId, $record->sourceDigest,
        ]);
        self::assertNull($record->attachment);
        self::assertSame(self::KEYS, array_keys($record->toArray()));
        self::assertTrue($pending->isConsumed());
    }

    /**
     * An imported record carries none of the ambient fields only capture fills:
     * no credential, guard, session, request, trace or user agent, even when
     * its builder was given them.
     *
     * @return void
     */
    public function testAnImportedRecordCarriesNoAmbientFields(): void
    {
        $pending = self::importBuilder()->usingCredential('key_01');

        $pending->fillGuard('web');
        $pending->fillSession('sess_ref_1');
        $pending->fillRequest('01932b4e-8a40-7000-8000-0000000000aa', '4bf92f3577b34da6a3ce929d0e0e4736');
        $pending->fillClient('198.51.100.4', 'Mozilla/5.0');

        $record = self::import($pending);

        self::assertSame([null, null, null, null, null, null], [
            $record->credentialId, $record->guard, $record->sessionId, $record->requestId, $record->traceId, $record->userAgent,
        ]);
        self::assertSame('198.51.100.4', $record->ip);
    }

    /**
     * An imported record's id is a UUID version 7 whose leading 48 bits are the
     * instant it was imported, never the instant its activity happened, so
     * imported ids sort near their recording.
     *
     * @return void
     */
    public function testAnImportedRecordsIdIsDrawnAtImport(): void
    {
        Str::createUuidsNormally();

        $record = self::import(self::importBuilder());
        $fields = Uuid::fromString($record->id)->getFields();
        $millis = hexdec(substr(str_replace('-', '', $record->id), 0, 12));

        self::assertInstanceOf(FieldsInterface::class, $fields);
        self::assertSame(7, $fields->getVersion());
        self::assertSame((int) self::importedAt()->format('Uv'), $millis);
        self::assertNotSame((int) (new \DateTimeImmutable(self::SOURCE_OCCURRED_AT))->format('Uv'), $millis);
    }

    /**
     * An imported record keeps the time its activity happened exactly as its
     * source gave it, however long before the import, and never takes the
     * import's time.
     *
     * @return void
     */
    public function testAnImportedRecordKeepsItsOccurrenceTime(): void
    {
        self::assertSame(self::SOURCE_OCCURRED_AT, self::import(self::importBuilder())->occurredAt);
        self::assertSame('2026-11-02T08:15:30.250001Z', self::import(self::importBuilder(), '2026-11-02T08:15:30.250001Z')->occurredAt);
    }

    /**
     * An imported record whose source did not know where the activity ran has
     * no origin, and one whose source did keeps it; its builder needs none.
     *
     * @return void
     */
    public function testAnImportedRecordMayHaveNoOrigin(): void
    {
        self::assertNull(self::import(self::importBuilder(), origin: null)->origin);
        self::assertNull(self::import(self::importBuilder(), origin: null)->toArray()['origin']);

        foreach (Origin::cases() as $origin) {
            self::assertSame($origin->value, self::import(self::importBuilder(), origin: $origin->value)->origin);
        }
    }

    /**
     * Rows of `[origin]`: values that are not an origin this package names.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownOrigins(): iterable
    {
        yield from [
            'empty'      => [''],
            'upper case' => ['HTTP'],
            'another'    => ['cli'],
            'padded'     => [' http'],
        ];
    }

    /**
     * An origin this package does not name is refused, never stored as given.
     *
     * @param  string  $origin
     * @return void
     */
    #[DataProvider('provideUnknownOrigins')]
    public function testFromImportRefusesAnUnknownOrigin(string $origin): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An imported record\'s origin must be one of `http`, `console`, `queue`, or null.');

        self::import(self::importBuilder(), origin: $origin);
    }

    /**
     * An imported record carries no artifact: a builder with a manifest is
     * refused, and so are minimised properties that hold a manifest descriptor.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnImportedRecordRefusesAnAttachment(): void
    {
        $manifest = self::manifest();
        $refusals = [
            'a manifest'   => static fn (): AuditRecord => self::import(self::importBuilder()->withManifest($manifest)),
            'a descriptor' => static fn (): AuditRecord => AuditRecord::fromImport(
                self::importBuilder(),
                new Minimised(['_audit' => ['manifest' => ['artifact_id' => $manifest->id]]], null, null),
                1,
                'finance',
                self::SOURCE_OCCURRED_AT,
                'http',
                RecordFactory::source(),
                self::importedAt(),
            ),
        ];

        foreach ($refusals as $label => $refusal) {
            try {
                $refusal();
                self::fail(sprintf('Expected an import with %s to be refused.', $label));
            } catch (\LogicException $exception) {
                self::assertSame(self::NO_ARTIFACT, $exception->getMessage(), $label);
            }
        }
    }

    /**
     * Rows of `[occurred at]`: times that are not an instant in the package's
     * form.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedTimes(): iterable
    {
        yield from [
            'empty'                  => [''],
            'no fraction'            => ['2026-11-01T12:00:00Z'],
            'milliseconds'           => ['2026-11-01T12:00:00.123Z'],
            'an offset'              => ['2026-11-01T12:00:00.123456+00:00'],
            'the storage form'       => ['2026-11-01 12:00:00.123456'],
            'a date that is not one' => ['2026-02-30T12:00:00.000000Z'],
            'hour 24'                => ['2026-11-01T24:00:00.000000Z'],
            'lower case'             => ['2026-11-01t12:00:00.123456z'],
        ];
    }

    /**
     * An occurrence time that is not ISO-8601 UTC with microseconds, on a date
     * and at a time that exist, is refused, never rolled over or repaired.
     *
     * @param  string  $occurredAt
     * @return void
     */
    #[DataProvider('provideMalformedTimes')]
    public function testFromImportRefusesAMalformedTime(string $occurredAt): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An imported record\'s occurrence time must be ISO-8601 UTC with microseconds, such as 2026-11-01T12:00:00.123456Z.');

        self::import(self::importBuilder(), $occurredAt);
    }

    /**
     * Importing a record uses the builder up, as capturing one does: a second
     * import of one builder is the reuse refusal.
     *
     * @return void
     */
    public function testImportingConsumesTheBuilder(): void
    {
        $pending = self::importBuilder();

        self::import($pending);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record is recorded once, and this one has already been recorded.');

        self::import($pending);
    }

    /**
     * The import's pending parameter is marked sensitive, as the capture's is:
     * it holds the record's values, and a refusal is thrown with it on the
     * stack.
     *
     * @return void
     */
    public function testTheImportsPendingParameterIsSensitive(): void
    {
        $parameter = (new \ReflectionMethod(AuditRecord::class, 'fromImport'))->getParameters()[0];

        self::assertSame('pending', $parameter->getName());
        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
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
     * A note with an owner is never stored in plaintext: with no encrypter it
     * is dropped, the properties hold only the diagnostic of its fixed path,
     * and the note's text appears nowhere in the encoded envelope.
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

        self::assertSame(['amount' => '1200.00', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['_audit.note']]]], $withProperties->properties);
        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['_audit.note']]]], $alone->properties);
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

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['_audit.note']]]], $record->properties);
        self::assertStringNotContainsString('Erasable remark', json_encode($record->toArray(), JSON_THROW_ON_ERROR));
    }

    /**
     * The record stores what it is given as minimised, and nothing of the
     * builder's raw address, context or properties reaches it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheRecordStoresTheMinimisedValues(): void
    {
        $pending = self::minimalBuilder()->withProperties(['raw_property' => 'raw']);
        $pending->fillClient('203.0.113.7', 'Mozilla/5.0');
        $pending->fillContext(['raw_context' => 'raw']);

        $record = AuditRecord::fromPending($pending, new Minimised(['kept' => 'property'], ['kept' => 'context'], '203.0.113.0'), 1, 'general', self::instant(), 'app-eu-1');

        self::assertSame('203.0.113.0', $record->ip);
        self::assertSame(['kept' => 'context'], $record->context);
        self::assertSame(['kept' => 'property'], $record->properties);
        self::assertSame('Mozilla/5.0', $record->userAgent);
        self::assertStringNotContainsString('raw', json_encode($record->toArray(), JSON_THROW_ON_ERROR));
    }

    /**
     * Minimising leaving nothing stores `null` for each, whatever the builder
     * held.
     *
     * @return void
     */
    public function testAMinimisedRecordOfNothingStoresNulls(): void
    {
        $pending = self::minimalBuilder()->withProperties(['raw_property' => 'raw']);
        $pending->fillClient('203.0.113.7', 'Mozilla/5.0');
        $pending->fillContext(['raw_context' => 'raw']);

        $record = AuditRecord::fromPending($pending, new Minimised(null, null, null), 1, 'general', self::instant(), 'app-eu-1');

        self::assertNull($record->ip);
        self::assertNull($record->context);
        self::assertNull($record->properties);
    }

    /**
     * The builder's parameter is marked sensitive: it holds the raw payload,
     * and a refusal here is thrown with it on the stack.
     *
     * @return void
     */
    public function testThePendingParameterIsSensitive(): void
    {
        $parameter = (new \ReflectionMethod(AuditRecord::class, 'fromPending'))->getParameters()[0];

        self::assertSame('pending', $parameter->getName());
        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * Rows of `[the order of the full builder's calls]`: forward, reversed,
     * outcome and timing first, and fillers first.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function providePermutations(): iterable
    {
        $forward = array_keys(self::calls());
        $first   = ['denied', 'transactional', 'failClosed'];
        $fillers = array_values(array_filter($forward, static fn (string $name): bool => str_starts_with($name, 'fill')));

        yield from [
            'forward'                  => [$forward],
            'reversed'                 => [array_reverse($forward)],
            'outcome and timing first' => [[...$first, ...array_values(array_diff($forward, $first))]],
            'fillers first'            => [[...$fillers, ...array_values(array_diff($forward, $fillers))]],
        ];
    }

    /**
     * The full builder's calls made in any of the orders give the same
     * envelope, byte for byte, under a pinned id.
     *
     * @param  list<string>  $order
     * @return void
     */
    #[DataProvider('providePermutations')]
    public function testPermutedCallOrdersGiveEqualEnvelopes(array $order): void
    {
        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString(self::ID));

        $calls     = self::calls();
        $reference = new PendingRecord;
        $permuted  = new PendingRecord;

        self::assertCount(count($calls), $order);

        foreach ($calls as $call) {
            $call($reference);
        }

        foreach ($order as $name) {
            $calls[$name]($permuted);
        }

        self::assertSame(self::build($reference)->toArray(), self::build($permuted)->toArray());
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

        $pending = self::minimalBuilder();

        AuditRecord::fromPending($pending, RecordFactory::minimisedOf($pending), 1, 'general', self::instant(), $sourceId, $sourceRegion);
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
        $minimised = RecordFactory::minimisedOf(self::minimalBuilder());

        $withRegion    = AuditRecord::fromPending(self::minimalBuilder(), $minimised, 1, 'general', self::instant(), 'app-eu-1', 'eu-west-2');
        $withoutRegion = AuditRecord::fromPending(self::minimalBuilder(), $minimised, 1, 'general', self::instant(), 'app-eu-1');
        $longest       = AuditRecord::fromPending(self::minimalBuilder(), $minimised, 1, 'general', self::instant(), str_repeat('é', 64), str_repeat('é', 32));

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
     * A builder with a manifest gives a record carrying the attachment of that
     * manifest, and its properties sign the descriptor that names it, its kind
     * included, after the caller's keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordWithAManifestCarriesItsAttachment(): void
    {
        $manifest   = self::manifest();
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());
        $pending    = self::minimalBuilder()->withProperties(['batch' => 'march'])->withManifest($manifest);

        $record = self::build($pending, attachment: $attachment);

        self::assertSame($attachment, $record->attachment);
        self::assertSame(['batch' => 'march', '_audit' => ['manifest' => $manifest->descriptor()]], $record->properties);
        self::assertSame('bulk', $manifest->descriptor()['kind']);
        self::assertTrue($pending->isConsumed());
    }

    /**
     * A record carries an artifact of any kind the same way: a disclosure of
     * nothing and an export are bound by a descriptor naming their kind.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordOfAnyKindCarriesItsAttachment(): void
    {
        foreach ([ArtifactKind::DISCLOSURE, ArtifactKind::EXPORT] as $kind) {
            $record = RecordFactory::withArtifact($kind, RecordFactory::canonical($kind, 0), 0);

            self::assertNotNull($record->attachment, $kind->value);
            self::assertSame($kind->value, $record->attachment->kind);
            self::assertSame(0, $record->attachment->memberCount);
            self::assertSame($kind->value, $record->properties['_audit']['manifest']['kind'] ?? null);
            self::assertSame($record->attachment, AuditRecord::fromEnvelope($record->toArray(), $record->attachment)->attachment);
        }
    }

    /**
     * A stored entry rebuilt to be read keeps its binding through an attachment
     * described from its own descriptor; one described from any other
     * descriptor, or none, is refused as an unbound attachment is.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordIsBoundToADescribedAttachment(): void
    {
        $record     = RecordFactory::bundled();
        $fields     = $record->toArray();
        $descriptor = $fields['properties']['_audit']['manifest'] ?? null;

        self::assertIsArray($descriptor);

        $described = Attachment::described($descriptor);
        $rebuilt   = AuditRecord::fromEnvelope($fields, $described);

        self::assertSame($described, $rebuilt->attachment);
        self::assertFalse($described->isSealed());
        self::assertSame($fields, $rebuilt->toArray());

        $others = [
            'another kind'  => Attachment::described(['kind' => 'export'] + $descriptor),
            'another count' => Attachment::described(['count' => 4] + $descriptor),
        ];

        foreach ($others as $label => $other) {
            try {
                AuditRecord::fromEnvelope($fields, $other);
                self::fail("Expected an attachment of {$label} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::MISMATCHED, $exception->getMessage(), $label);
            }
        }
    }

    /**
     * A record without a manifest carries no attachment.
     *
     * @return void
     */
    public function testARecordWithoutAManifestCarriesNoAttachment(): void
    {
        self::assertNull(self::build(self::fullBuilder())->attachment);
        self::assertNull(self::build(self::minimalBuilder())->attachment);
    }

    /**
     * A builder with a manifest gives no record without the attachment of that
     * manifest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAManifestWithoutAnAttachmentIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::UNBOUND);

        self::build(self::minimalBuilder()->withManifest(self::manifest()));
    }

    /**
     * A builder with a manifest gives no record with the attachment of another
     * manifest, even one of the same members, whose id is another.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnAttachmentOfAnotherArtifactIsRefused(): void
    {
        $other = Attachment::sealed(self::manifest(), RecordFactory::encrypter());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::UNBOUND);

        self::build(self::minimalBuilder()->withManifest(self::manifest()), attachment: $other);
    }

    /**
     * A record without a manifest is refused an attachment.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnAttachmentWithoutAManifestIsRefused(): void
    {
        $attachment = Attachment::sealed(self::manifest(), RecordFactory::encrypter());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::UNBOUND);

        self::build(self::minimalBuilder(), attachment: $attachment);
    }

    /**
     * The attachment must be the one the minimised properties describe: a
     * minimisation that lost the descriptor, or that describes another
     * manifest, is refused even with the builder's own attachment.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheMinimisedDescriptorMustDescribeTheAttachment(): void
    {
        $manifest   = self::manifest();
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());

        $minimisations = [
            'no descriptor'      => RecordFactory::minimisedOf(self::minimalBuilder()),
            'another descriptor' => RecordFactory::minimisedOf(self::minimalBuilder()->withManifest(self::manifest())),
        ];

        foreach ($minimisations as $label => $minimised) {
            try {
                AuditRecord::fromPending(self::minimalBuilder()->withManifest($manifest), $minimised, 1, 'finance', self::instant(), 'app-eu-1', null, $attachment);
                self::fail("Expected a record with {$label} to be refused.");
            } catch (\LogicException $exception) {
                self::assertSame(self::UNBOUND, $exception->getMessage(), $label);
            }
        }
    }

    /**
     * The attachment is never in the envelope: the record's 32 keys stay
     * exactly what is signed, and the members appear nowhere in it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheAttachmentIsNeverInTheEnvelope(): void
    {
        $record   = RecordFactory::bundled();
        $envelope = $record->toArray();

        self::assertNotNull($record->attachment);
        self::assertSame(self::KEYS, array_keys($envelope));
        self::assertStringNotContainsString($record->attachment->members, json_encode($envelope, JSON_THROW_ON_ERROR));
        self::assertSame($record->attachment->id, $envelope['properties']['_audit']['manifest']['artifact_id'] ?? null);
    }

    /**
     * A bundle's record rebuilt from its envelope with its attachment keeps
     * both, whatever order the descriptor's keys were decoded in.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFromEnvelopeKeepsTheAttachmentItsDescriptorNames(): void
    {
        $record = RecordFactory::bundled();
        $fields = $record->toArray();

        self::assertNotNull($record->attachment);

        $rebuilt = AuditRecord::fromEnvelope($fields, $record->attachment);

        self::assertSame($fields, $rebuilt->toArray());
        self::assertSame($record->attachment, $rebuilt->attachment);

        $properties = $fields['properties'] ?? [];

        self::assertIsArray($properties['_audit'] ?? null);
        self::assertIsArray($properties['_audit']['manifest'] ?? null);

        $properties['_audit']['manifest'] = array_reverse($properties['_audit']['manifest'], true);

        self::assertSame($record->attachment, AuditRecord::fromEnvelope(['properties' => $properties] + $fields, $record->attachment)->attachment);
    }

    /**
     * An envelope whose properties sign a descriptor is refused without an
     * attachment, so a record never silently loses its members.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFromEnvelopeRefusesADescriptorWithoutAnAttachment(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MISMATCHED);

        AuditRecord::fromEnvelope(RecordFactory::bundled()->toArray());
    }

    /**
     * An envelope whose properties sign no descriptor is refused an attachment,
     * whether its properties hold metadata or are `null`.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFromEnvelopeRefusesAnAttachmentWithoutADescriptor(): void
    {
        $attachment = RecordFactory::bundled()->attachment;
        $fields     = self::build(self::minimalBuilder()->withNote('Checked'))->toArray();

        self::assertNotNull($attachment);

        foreach ([$fields, ['properties' => null] + $fields, ['properties' => ['_audit' => 'manifest']] + $fields] as $envelope) {
            try {
                AuditRecord::fromEnvelope($envelope, $attachment);
                self::fail('Expected an attachment without a descriptor to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::MISMATCHED, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[what replaces the signed descriptor]`: a descriptor of another
     * artifact or kind, a changed count, a malformed descriptor and one key
     * missing, the kind among them.
     *
     * @return iterable<string, array{0: array<string, int|string|null>|string|null}>
     */
    public static function provideOtherDescriptors(): iterable
    {
        yield from [
            'another artifact' => [['artifact_id' => '01932b4e-8a40-7000-8000-00000000000f']],
            'a changed count'  => [['count' => 4]],
            'another kind'     => [['kind' => 'export']],
            'no kind'          => [['kind' => null]],
            'a changed digest' => [['digest' => str_repeat('a', 64)]],
            'a string'         => ['01932b4e-8a40-7000-8000-00000000000f'],
            'null'             => [null],
            'no digest'        => [['digest' => null]],
        ];
    }

    /**
     * An attachment the signed descriptor does not describe is refused.
     *
     * @param  array<string, int|string|null>|string|null  $replacement
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideOtherDescriptors')]
    public function testFromEnvelopeRefusesAnAttachmentTheDescriptorDoesNotDescribe(array|string|null $replacement): void
    {
        $record     = RecordFactory::bundled();
        $fields     = $record->toArray();
        $properties = $fields['properties'] ?? [];

        self::assertIsArray($properties['_audit'] ?? null);
        self::assertIsArray($properties['_audit']['manifest'] ?? null);

        $properties['_audit']['manifest'] = is_array($replacement)
            ? array_filter($replacement + $properties['_audit']['manifest'], static fn (mixed $value): bool => $value !== null)
            : $replacement;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MISMATCHED);

        AuditRecord::fromEnvelope(['properties' => $properties] + $fields, $record->attachment);
    }

    /**
     * The attachment is marked sensitive on the way in and where the record
     * holds it.
     *
     * @return void
     */
    public function testTheAttachmentIsMarkedSensitive(): void
    {
        $parameters = [
            new \ReflectionParameter([AuditRecord::class, '__construct'], 'attachment'),
            new \ReflectionParameter([AuditRecord::class, 'fromPending'], 'attachment'),
            new \ReflectionParameter([AuditRecord::class, 'fromEnvelope'], 'attachment'),
        ];

        foreach ($parameters as $parameter) {
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), $parameter->getDeclaringFunction()->getName());
        }
    }

    /**
     * The full builder's calls, by name, each on its own; its note has no
     * owner, so the envelope keeps it.
     *
     * @return array<string, \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void>
     */
    private static function calls(): array
    {
        return [
            'event' => static function (PendingRecord $pending): void {
                $pending->event('invoice.approved');
            },
            'on' => static function (PendingRecord $pending): void {
                $pending->on(Reference::of('invoice', 'inv_0042'));
            },
            'by' => static function (PendingRecord $pending): void {
                $pending->by(Reference::of('user', 42));
            },
            'asPrincipal' => static function (PendingRecord $pending): void {
                $pending->asPrincipal(Reference::of('team', '7'));
            },
            'forTenant' => static function (PendingRecord $pending): void {
                $pending->forTenant(Reference::of('organisation', 'org_01'));
            },
            'usingCredential' => static function (PendingRecord $pending): void {
                $pending->usingCredential('key_01');
            },
            'correlatedWith' => static function (PendingRecord $pending): void {
                $pending->correlatedWith('app:ticket-123');
            },
            'withProperties' => static function (PendingRecord $pending): void {
                $pending->withProperties(['amount' => '1200.00', 'currency' => 'GBP', 'lines' => [1, 2]]);
            },
            'withNote' => static function (PendingRecord $pending): void {
                $pending->withNote('Approved after review');
            },
            'withIdentifier' => static function (PendingRecord $pending): void {
                $pending->withIdentifier('alice@example.com');
            },
            'denied' => static function (PendingRecord $pending): void {
                $pending->denied('policy');
            },
            'transactional' => static function (PendingRecord $pending): void {
                $pending->transactional('business');
            },
            'failClosed' => static function (PendingRecord $pending): void {
                $pending->failClosed();
            },
            'fillGuard' => static function (PendingRecord $pending): void {
                $pending->fillGuard('web');
            },
            'fillSession' => static function (PendingRecord $pending): void {
                $pending->fillSession('sess_ref_1');
            },
            'fillRequest' => static function (PendingRecord $pending): void {
                $pending->fillRequest('01932b4e-8a40-7000-8000-0000000000aa', '4bf92f3577b34da6a3ce929d0e0e4736');
            },
            'fillClient' => static function (PendingRecord $pending): void {
                $pending->fillClient('203.0.113.7', 'Mozilla/5.0');
            },
            'fillOrigin' => static function (PendingRecord $pending): void {
                $pending->fillOrigin(Origin::HTTP);
            },
            'fillContext' => static function (PendingRecord $pending): void {
                $pending->fillContext(['route' => 'invoices.approve', 'method' => 'POST']);
            },
        ];
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
     * A builder as the importer makes one: a code, the references, a denial
     * with its reason, a correlation id, properties, and the IP address and
     * context of the source's line, and no origin.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function importBuilder(): PendingRecord
    {
        $pending = (new PendingRecord)
            ->event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', 42))
            ->asPrincipal(Reference::of('team', '7'))
            ->forTenant(Reference::of('organisation', 'org_01'))
            ->correlatedWith('legacy:ticket-7')
            ->withProperties(['amount' => '1200.00'])
            ->denied('policy');

        $pending->fillClient('198.51.100.4', null);
        $pending->fillContext(['route' => 'invoices.approve']);

        return $pending;
    }

    /**
     * The imported record of the builder, of the occurrence time and origin
     * given, from the factory's source, imported at the import time.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  string  $occurredAt
     * @param  ?string  $origin
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function import(PendingRecord $pending, string $occurredAt = self::SOURCE_OCCURRED_AT, ?string $origin = 'http'): AuditRecord
    {
        return AuditRecord::fromImport($pending, RecordFactory::minimisedOf($pending), 1, 'finance', $occurredAt, $origin, RecordFactory::source(), self::importedAt());
    }

    /**
     * The instant the imported records are imported.
     *
     * @return \DateTimeImmutable
     */
    private static function importedAt(): \DateTimeImmutable
    {
        return new \DateTimeImmutable(self::IMPORTED_AT);
    }

    /**
     * The captured record of the builder, as the golden record is built, with
     * the attachment given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\DateTimeInterface  $occurredAt
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function build(PendingRecord $pending, ?\DateTimeInterface $occurredAt = null, ?Attachment $attachment = null): AuditRecord
    {
        return AuditRecord::fromPending($pending, RecordFactory::minimisedOf($pending), 2, 'finance', $occurredAt ?? self::instant(), 'app-eu-1', 'eu-west-2', $attachment);
    }

    /**
     * A manifest of three invoices, made anew, so each has its own id.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \JsonException
     */
    private static function manifest(): Manifest
    {
        return Manifest::of(RecordFactory::members(3), 3, 65536);
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
