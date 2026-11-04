<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for an entry as a viewer is shown it: its snake-case array, with
 * references as pairs, enums as values and times as instants; times in UTC to
 * the microsecond, whatever the default time zone; an imported entry's source
 * digest; and an artifact shown by its descriptor alone, never its id or its
 * members.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailEntry::class)]
final class TrailEntryTest extends TestCase
{
    /** @var string The entry's id. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var string A digest in lower-case hex. */
    private const string DIGEST = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

    /** @var string The keyed digest of an imported entry's source assertion, in lower-case hex. */
    private const string SOURCE_DIGEST = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

    /** @var string The default time zone before a test changed it. */
    private string $timeZone = 'UTC';

    /**
     * Remember the default time zone.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->timeZone = date_default_timezone_get();
    }

    /**
     * Restore the default time zone.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        date_default_timezone_set($this->timeZone);

        parent::tearDown();
    }

    /**
     * The array has every field under its snake-case key, in order: the
     * references as `type` and `id` pairs or `null`, the enums as their values,
     * the times as instants and the display arrays as they are.
     *
     * @return void
     */
    public function testToArrayIsSnakeCaseWithReferencesAndInstants(): void
    {
        self::assertSame([
            'id'                => self::ID,
            'event'             => 'invoice.approved',
            'event_version'     => 2,
            'record_version'    => 1,
            'integrity_version' => 1,
            'category'          => 'finance',
            'outcome'           => 'denied',
            'reason'            => 'over_limit',
            'actor'             => ['type' => 'user', 'id' => '42'],
            'subject'           => ['type' => 'invoice', 'id' => 'inv_0042'],
            'principal'         => null,
            'tenant'            => ['type' => 'organisation', 'id' => 'org_01'],
            'credential_id'     => 'cred_7',
            'guard'             => 'web',
            'session_id'        => 'sess_1',
            'request_id'        => 'req_1',
            'trace_id'          => '4bf92f3577b34da6a3ce929d0e0e4736',
            'correlation_id'    => 'app:ticket-123',
            'origin'            => 'http',
            'provenance'        => 'imported',
            'source_id'         => 'app-eu-1',
            'source_region'     => 'eu-west-2',
            'source_record_id'  => 'legacy-9',
            'import_batch_id'   => '01932b4e-8a40-7000-8000-0000000000ff',
            'source_digest'     => self::SOURCE_DIGEST,
            'ip'                => '[ENCRYPTED]',
            'user_agent'        => 'Mozilla/5.0',
            'context'           => ['route' => 'invoices.approve'],
            'properties'        => ['amount' => '1200.00', 'lines' => [['sku' => 'A1']]],
            'occurred_at'       => '2026-11-01T12:00:00.123456Z',
            'recorded_at'       => '2026-11-01T12:00:01.000001Z',
            'key_id'            => 'k1',
            'hmac'              => self::HMAC,
            'manifest'          => ['kind' => 'bulk', 'count' => 3, 'digest' => self::DIGEST],
        ], self::entry()->toArray());
    }

    /**
     * An entry with no references, origin, source digest or manifest gives
     * `null` for each.
     *
     * @return void
     */
    public function testToArrayGivesNullForWhatIsAbsent(): void
    {
        $array = self::entry(['actor' => null, 'subject' => null, 'tenant' => null, 'origin' => null, 'sourceDigest' => null, 'manifest' => null])->toArray();

        self::assertNull($array['actor']);
        self::assertNull($array['subject']);
        self::assertNull($array['tenant']);
        self::assertNull($array['origin']);
        self::assertNull($array['source_digest']);
        self::assertNull($array['manifest']);
    }

    /**
     * Times a stored entry holds are read as instants in UTC to the
     * microsecond, whatever the default time zone, and an instant given in
     * another zone is given in the array in UTC.
     *
     * @return void
     */
    public function testTimesAreUtcInstantsToTheMicrosecond(): void
    {
        date_default_timezone_set('Pacific/Auckland');

        $stored = StoredEntry::fromRow((new RowCodec)->encode(RecordFactory::finalisedBundle(1)), new RowCodec);
        $entry  = self::projector()->project([$stored], false)->entries[0];

        self::assertSame('UTC', $entry->occurredAt->getTimezone()->getName());
        self::assertSame('UTC', $entry->recordedAt->getTimezone()->getName());
        self::assertSame('2026-11-01 12:00:00.123456', $entry->occurredAt->format('Y-m-d H:i:s.u'));
        self::assertSame('2026-11-01 12:00:01.654321', $entry->recordedAt->format('Y-m-d H:i:s.u'));
        self::assertSame(RecordFactory::OCCURRED_AT, $entry->toArray()['occurred_at']);
        self::assertSame(RecordFactory::RECORDED_AT, $entry->toArray()['recorded_at']);

        $zoned = self::entry(['occurredAt' => new CarbonImmutable('2026-11-02 01:00:00.000007', 'Pacific/Auckland')]);

        self::assertSame('2026-11-01T12:00:00.000007Z', $zoned->toArray()['occurred_at']);
    }

    /**
     * A stored imported entry is projected with its source digest, and a stored
     * captured entry with none.
     *
     * @return void
     */
    public function testTheSourceDigestIsProjectedFromTheStoredEntry(): void
    {
        $imported = new FinalisedRecord(RecordFactory::imported(), RecordFactory::IMPORTED_AT, 1, 'k1', self::HMAC);
        $entries  = self::projector()->project([
            StoredEntry::fromRow((new RowCodec)->encode($imported), new RowCodec),
            StoredEntry::fromRow((new RowCodec)->encode(RecordFactory::finalisedBundle(1)), new RowCodec),
        ], false)->entries;

        self::assertSame(RecordFactory::source()->sourceDigest, $entries[0]->sourceDigest);
        self::assertSame(RecordFactory::source()->sourceDigest, $entries[0]->toArray()['source_digest']);
        self::assertSame(Provenance::IMPORTED, $entries[0]->provenance);
        self::assertNull($entries[1]->sourceDigest);
        self::assertNull($entries[1]->toArray()['source_digest']);
    }

    /**
     * An entry with an artifact shows its kind, count and digest alone: not its
     * artifact id, which only the stored descriptor holds, and never its
     * members, which are not loaded.
     *
     * @return void
     */
    public function testOnlyTheManifestDescriptorIsExposed(): void
    {
        $finalised = RecordFactory::finalisedWithArtifact(ArtifactKind::DISCLOSURE, RecordFactory::canonical(ArtifactKind::DISCLOSURE, 2), 2);
        $stored    = StoredEntry::fromRow((new RowCodec)->encode($finalised), new RowCodec);
        $entry     = self::projector()->project([$stored], false)->entries[0];
        $array     = $entry->toArray();

        $attachment = $finalised->record->attachment;

        self::assertNotNull($attachment);
        self::assertSame(['kind' => 'disclosure', 'count' => 2, 'digest' => $attachment->digest], $entry->manifest);
        self::assertSame($entry->manifest, $array['manifest']);
        self::assertArrayNotHasKey('_audit', $entry->properties);

        $shown = (string) json_encode($array);

        self::assertStringNotContainsString($attachment->id, $shown);
        self::assertStringNotContainsString((string) $attachment->members, $shown);
        self::assertStringNotContainsString('artifact_id', $shown);
    }

    /**
     * The credential id is kept out of a stack trace's frames, and so are the
     * display arrays.
     *
     * @return void
     */
    public function testWhatAnEntryHoldsIsSensitive(): void
    {
        foreach (['credentialId', 'context', 'properties'] as $parameter) {
            self::assertCount(1, (new \ReflectionParameter([TrailEntry::class, '__construct'], $parameter))->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }

    /**
     * An entry of every field, with the fields given in place of the defaults,
     * by name.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private static function entry(array $fields = []): TrailEntry
    {
        $defaults = [
            'id'               => self::ID,
            'event'            => 'invoice.approved',
            'eventVersion'     => 2,
            'recordVersion'    => 1,
            'integrityVersion' => 1,
            'category'         => 'finance',
            'outcome'          => Outcome::DENIED,
            'reason'           => 'over_limit',
            'actor'            => Reference::of('user', '42'),
            'subject'          => Reference::of('invoice', 'inv_0042'),
            'principal'        => null,
            'tenant'           => Reference::of('organisation', 'org_01'),
            'credentialId'     => 'cred_7',
            'guard'            => 'web',
            'sessionId'        => 'sess_1',
            'requestId'        => 'req_1',
            'traceId'          => '4bf92f3577b34da6a3ce929d0e0e4736',
            'correlationId'    => 'app:ticket-123',
            'origin'           => Origin::HTTP,
            'provenance'       => Provenance::IMPORTED,
            'sourceId'         => 'app-eu-1',
            'sourceRegion'     => 'eu-west-2',
            'sourceRecordId'   => 'legacy-9',
            'importBatchId'    => '01932b4e-8a40-7000-8000-0000000000ff',
            'sourceDigest'     => self::SOURCE_DIGEST,
            'ip'               => '[ENCRYPTED]',
            'userAgent'        => 'Mozilla/5.0',
            'context'          => ['route' => 'invoices.approve'],
            'properties'       => ['amount' => '1200.00', 'lines' => [['sku' => 'A1']]],
            'occurredAt'       => new CarbonImmutable('2026-11-01 12:00:00.123456', 'UTC'),
            'recordedAt'       => new CarbonImmutable('2026-11-01 12:00:01.000001', 'UTC'),
            'keyId'            => 'k1',
            'hmac'             => self::HMAC,
            'manifest'         => ['kind' => 'bulk', 'count' => 3, 'digest' => self::DIGEST],
        ];

        // @phpstan-ignore argument.type
        return new TrailEntry(...[...$defaults, ...$fields]);
    }

    /**
     * The projector of the package's own field reader, which reads nothing of a
     * page that does not reveal its fields, with a signer no entry here
     * reaches.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\EntryProjector
     */
    private static function projector(): EntryProjector
    {
        $signer = new RecordSigner(new KeyRing(new IntegritySettings(new Repository(['app' => ['key' => str_repeat('k', 32)]]))));

        return new EntryProjector(new SealedFieldReader, new RecordingExceptionHandler, $signer);
    }
}
