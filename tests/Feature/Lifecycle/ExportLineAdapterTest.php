<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\ExportLineAdapter;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\TestCase;

/**
 * Feature tests for reading another installation's export lines: the fields
 * they map to, the identity a captured and an imported line keep, the lines of
 * another source or of this installation refused, reserved codes, foreign
 * envelopes and the exporter's metadata removed and counted, and its integrity
 * fields ignored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportLineAdapter::class)]
final class ExportLineAdapterTest extends TestCase
{
    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The exporting installation, the import's source. */
    private const string EXPORTER = 'app-us-1';

    /** @var string The id the exporter captured the record under. */
    private const string ID = '01a196fb-1600-7328-bff7-a78c4cedcf62';

    /** @var array{v: int, k: string, c: string} An envelope the exporter sealed. */
    private const array ENVELOPE = ['v' => 1, 'k' => 'subject:user:42:1', 'c' => 'ciphertext'];

    /** @var string The file every source names. */
    private string $path = '';

    /**
     * Freeze the clock, name this installation's source and make the file every
     * source names.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);

        $this->path = (string) tempnam(sys_get_temp_dir(), 'import-export-');
    }

    /**
     * Put the clock back and remove the file.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        if (is_file($this->path)) {
            unlink($this->path);
        }

        parent::tearDown();
    }

    /**
     * Another installation's captured line maps field by field: its code, time,
     * outcome and reason, its references from their flattened columns, its
     * category, correlation id, properties, context, origin and IP.
     *
     * @return void
     */
    public function testAnotherInstallationsExportLineMaps(): void
    {
        $line = $this->parsed(self::exported());

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(4, $line->number);
        self::assertSame('invoice.approved', $line->event);
        self::assertSame('2026-11-01T12:00:00.000001Z', $line->occurredAt);
        self::assertSame(Outcome::DENIED, $line->outcome);
        self::assertSame('over_limit', $line->reason);
        self::assertSame(['type' => 'user', 'id' => '42'], $line->actor?->toArray());
        self::assertSame(['type' => 'invoice', 'id' => 'inv_0042'], $line->subject?->toArray());
        self::assertNull($line->principal);
        self::assertSame(['type' => 'organisation', 'id' => 'org_01'], $line->tenant?->toArray());
        self::assertSame('finance', $line->category);
        self::assertSame('app:ticket-123', $line->correlationId);
        self::assertSame(['amount' => '1200.00'], $line->properties);
        self::assertSame(['method' => 'POST', 'route' => 'invoices.approve'], $line->context);
        self::assertSame('http', $line->origin);
        self::assertSame('203.0.113.7', $line->ip);
        self::assertSame(0, $line->dropped);
    }

    /**
     * A line the exporter captured is asserted by the exporter, under its own
     * id there, in the import's region, or the line's when the import names
     * none.
     *
     * @return void
     */
    public function testACapturedLineKeepsItsIdAsTheSourceRecordId(): void
    {
        $line = $this->parsed(self::exported());

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(self::EXPORTER, $line->sourceId);
        self::assertSame(self::ID, $line->sourceRecordId);
        self::assertSame('us-east-1', $line->sourceRegion);

        $unnamed = $this->adapter()->parse(1, CanonicalEncoder::encode(self::exported()), ImportSource::fromExport($this->path, self::EXPORTER));

        self::assertInstanceOf(ImportLine::class, $unnamed);
        self::assertSame('us-west-2', $unnamed->sourceRegion);
    }

    /**
     * A line the exporter had itself imported keeps its upstream source, its
     * record id there and its region, never the exporter's own identity.
     *
     * @return void
     */
    public function testAnImportedLineKeepsItsUpstreamIdentity(): void
    {
        $upstream = ['provenance' => 'imported', 'source_id' => 'crm-eu', 'source_region' => 'eu-west-2', 'source_record_id' => 'rec-0042'];
        $line     = $this->parsed([...self::exported(), ...$upstream, 'origin' => null]);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame('crm-eu', $line->sourceId);
        self::assertSame('rec-0042', $line->sourceRecordId);
        self::assertSame('eu-west-2', $line->sourceRegion);
        self::assertNull($line->origin);
    }

    /**
     * An imported line without its upstream record id is `MISSING_FIELD`.
     *
     * @return void
     */
    public function testAnImportedLineWithoutItsUpstreamIdIsRejected(): void
    {
        self::assertSame(ImportRejection::MISSING_FIELD, $this->parsed([...self::exported(), 'provenance' => 'imported', 'source_id' => 'crm-eu']));
    }

    /**
     * A line whose source, upstream or the exporter's own, is this installation
     * is `OWN_SOURCE`: its own records come back through replay.
     *
     * @return void
     */
    public function testAnUpstreamSourceOfThisInstallationIsRejected(): void
    {
        self::assertSame(ImportRejection::OWN_SOURCE, $this->parsed([...self::exported(), 'provenance' => 'imported', 'source_id' => self::OWN, 'source_record_id' => 'rec-1']));
        self::assertSame(ImportRejection::OWN_SOURCE, $this->parsed([...self::exported(), 'source_id' => self::OWN]));
    }

    /**
     * A captured line of a source other than the import's is `SOURCE_MISMATCH`.
     *
     * @return void
     */
    public function testALineOfAnotherSourceIsRejected(): void
    {
        self::assertSame(ImportRejection::SOURCE_MISMATCH, $this->parsed([...self::exported(), 'source_id' => 'app-ap-1']));
    }

    /**
     * A reserved code is `RESERVED_CODE`: this installation never imports
     * another's own activity as its evidence.
     *
     * @return void
     */
    public function testAReservedCodeIsRejected(): void
    {
        self::assertSame(ImportRejection::RESERVED_CODE, $this->parsed([...self::exported(), 'event' => 'audit_log.trail_read']));
    }

    /**
     * Every envelope the exporter sealed in the properties and the context is
     * removed and counted, never kept as if it were this installation's.
     *
     * @return void
     */
    public function testForeignEnvelopesAreDroppedAndCounted(): void
    {
        $line = $this->parsed([...self::exported(), 'properties' => ['amount' => '1200.00', 'iban' => self::ENVELOPE], 'context' => ['route' => 'x', 'token' => self::ENVELOPE]]);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(['amount' => '1200.00'], $line->properties);
        self::assertSame(['route' => 'x'], $line->context);
        self::assertSame(2, $line->dropped);
    }

    /**
     * An envelope nested deep in the properties, in maps and lists, is removed
     * and counted.
     *
     * @return void
     */
    public function testANestedForeignEnvelopeIsDropped(): void
    {
        $line = $this->parsed([...self::exported(), 'properties' => ['a' => ['b' => [['c' => self::ENVELOPE, 'd' => 1], self::ENVELOPE]]]]);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(['a' => ['b' => [['d' => 1]]]], $line->properties);
        self::assertSame(2, $line->dropped);
    }

    /**
     * An IP address the exporter encrypted, stored as its envelope's JSON, is
     * removed and counted.
     *
     * @return void
     */
    public function testAnEncryptedIpIsDropped(): void
    {
        $line = $this->parsed([...self::exported(), 'ip' => CanonicalEncoder::encode(self::ENVELOPE)]);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertNull($line->ip);
        self::assertSame(1, $line->dropped);
    }

    /**
     * The exporter's `_audit` metadata, a manifest descriptor naming an
     * artifact that is not imported among it, is removed whole and counted
     * once, and the rest of the properties are kept.
     *
     * @return void
     */
    public function testTheManifestDescriptorAndMetadataAreDropped(): void
    {
        $manifest = ['artifact_id' => '01a1a530-b9f9-70da-8839-4576860a36bf', 'count' => 3, 'digest' => str_repeat('a', 64), 'kind' => 'bulk'];
        $metadata = ['manifest' => $manifest, 'note' => self::ENVELOPE, 'omitted' => ['iban']];
        $line     = $this->parsed([...self::exported(), 'properties' => ['_audit' => $metadata, 'batch' => 'march']]);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(['batch' => 'march'], $line->properties);
        self::assertSame(1, $line->dropped);

        $only = $this->parsed([...self::exported(), 'properties' => ['_audit' => $metadata]]);

        self::assertInstanceOf(ImportLine::class, $only);
        self::assertSame([], $only->properties);
    }

    /**
     * The integrity fields and the exporter's own metadata are ignored: a line
     * with other values in every one of them maps to the same line.
     *
     * @return void
     */
    public function testIntegrityFieldsAreIgnored(): void
    {
        $other = [...self::exported(),
            'recorded_at'       => '2027-01-01T00:00:00.000000Z',
            'integrity_version' => 99,
            'key_id'            => 'not-a-key',
            'hmac'              => 'not-an-hmac',
            'credential_id'     => 'cred_1',
            'guard'             => 'api',
            'session_id'        => 'session-1',
            'request_id'        => 'request-1',
            'trace_id'          => str_repeat('a', 32),
            'user_agent'        => 'Another/1.0',
            'event_version'     => 7,
            'import_batch_id'   => '01a196fb-1600-7328-bff7-a78c4cedcf63',
            'source_digest'     => str_repeat('b', 64),
        ];

        self::assertEquals($this->parsed(self::exported()), $this->parsed($other));
    }

    /**
     * Rows of `[record version]`: versions this package does not read.
     *
     * @return iterable<string, array{0: int|string}>
     */
    public static function provideUnsupportedVersions(): iterable
    {
        yield from [
            'a later version'  => [2],
            'no version'       => [0],
            'a string version' => ['1'],
        ];
    }

    /**
     * A record version this package does not read is `UNSUPPORTED_VERSION`, and
     * one left out is `MISSING_FIELD`.
     *
     * @param  int|string  $version
     * @return void
     */
    #[DataProvider('provideUnsupportedVersions')]
    public function testAnUnsupportedRecordVersionIsRejected(int|string $version): void
    {
        self::assertSame(ImportRejection::UNSUPPORTED_VERSION, $this->parsed([...self::exported(), 'record_version' => $version]));

        $line = self::exported();

        unset($line['record_version']);

        self::assertSame(ImportRejection::MISSING_FIELD, $this->parsed($line));
    }

    /**
     * Rows of `[line, reason]`: lines the adapter cannot read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection}>
     */
    public static function provideRejectedLines(): iterable
    {
        $line = self::exported();

        yield from [
            'a column it has not'     => [[...$line, 'note' => 'x'], ImportRejection::UNKNOWN_FIELD],
            'no id'                   => [[...$line, 'id' => null], ImportRejection::MISSING_FIELD],
            'no provenance'           => [[...$line, 'provenance' => null], ImportRejection::MISSING_FIELD],
            'no source'               => [[...$line, 'source_id' => null], ImportRejection::MISSING_FIELD],
            'no event'                => [[...$line, 'event' => null], ImportRejection::MISSING_FIELD],
            'another provenance'      => [[...$line, 'provenance' => 'witnessed'], ImportRejection::INVALID_FIELD],
            'a number source'         => [[...$line, 'source_id' => 7], ImportRejection::INVALID_FIELD],
            'a number region'         => [[...$line, 'source_region' => 7], ImportRejection::INVALID_FIELD],
            'a half actor'            => [[...$line, 'actor_id' => null], ImportRejection::INVALID_FIELD],
            'a time without its zone' => [[...$line, 'occurred_at' => '2026-11-01 12:00:00.000001'], ImportRejection::INVALID_TIME],
            'a future time'           => [[...$line, 'occurred_at' => '2026-11-03T00:00:00.000000Z'], ImportRejection::FUTURE_TIME],
            'a number id'             => [[...$line, 'id' => 7], ImportRejection::INVALID_FIELD],
        ];
    }

    /**
     * Each line the adapter cannot read is rejected for its reason.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $line
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection  $reason
     * @return void
     */
    #[DataProvider('provideRejectedLines')]
    public function testALineItCannotReadIsRejected(array $line, ImportRejection $reason): void
    {
        self::assertSame($reason, $this->parsed($line));
    }

    /**
     * A line that is not a JSON object is `MALFORMED_JSON`.
     *
     * @return void
     */
    public function testALineThatIsNotAnObjectIsMalformed(): void
    {
        foreach (['{"id":', '[1]', 'null', ''] as $text) {
            self::assertSame(ImportRejection::MALFORMED_JSON, $this->adapter()->parse(1, $text, $this->source()), $text);
        }
    }

    /**
     * Every column of a line the exporter captured, as its export writes it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<string, mixed>
     */
    private static function exported(): array
    {
        $line = [
            ...array_fill_keys(array_keys(RowCodec::COLUMNS), null),
            'id'                => self::ID,
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'finance',
            'outcome'           => 'denied',
            'reason'            => 'over_limit',
            'actor_type'        => 'user',
            'actor_id'          => '42',
            'subject_type'      => 'invoice',
            'subject_id'        => 'inv_0042',
            'tenant_type'       => 'organisation',
            'tenant_id'         => 'org_01',
            'guard'             => 'web',
            'correlation_id'    => 'app:ticket-123',
            'origin'            => 'http',
            'provenance'        => 'captured',
            'source_id'         => self::EXPORTER,
            'source_region'     => 'us-west-2',
            'ip'                => '203.0.113.7',
            'user_agent'        => 'Mozilla/5.0',
            'context'           => ['method' => 'POST', 'route' => 'invoices.approve'],
            'properties'        => ['amount' => '1200.00'],
            'occurred_at'       => '2026-11-01T12:00:00.000001Z',
            'recorded_at'       => '2026-11-01T12:00:00.000001Z',
            'integrity_version' => 1,
            'key_id'            => 'd03d4735ce37bd961',
            'hmac'              => 'ce44d851086d1efb05d5b050c5ff7034c4edfa6ba2bbf8fb95f767848f7299ce',
        ];

        self::assertSame(array_keys(RowCodec::COLUMNS), array_keys($line));

        return $line;
    }

    /**
     * The line given, encoded as the export writes it, read as line 4 of the
     * import's source.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $line
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private function parsed(array $line): ImportLine|ImportRejection
    {
        return $this->adapter()->parse(4, CanonicalEncoder::encode($line), $this->source());
    }

    /**
     * The import's source: the exporting installation, in its region.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource
     */
    private function source(): ImportSource
    {
        return ImportSource::fromExport($this->path, self::EXPORTER, 'us-east-1');
    }

    /**
     * The adapter the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ExportLineAdapter
     */
    private function adapter(): ExportLineAdapter
    {
        return app(ExportLineAdapter::class);
    }
}
