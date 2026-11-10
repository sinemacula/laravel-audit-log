<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportRecordBuilder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Feature tests for building an imported record from a line: the definition it
 * is built under, registered or the default in the line's category, the code
 * refused while registration is required, no contributor run, the record's
 * fields and source, its refusals, and a dry run that encrypts nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportRecordBuilder::class)]
final class ImportRecordBuilderTest extends TestCase
{
    /** @var string The code every line names. */
    private const string CODE = 'invoice.approved';

    /** @var string The batch every record comes in. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var string When every record is imported. */
    private const string IMPORTED_AT = '2026-11-02 09:00:00.250000';

    /** @var \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue The catalogue every build reads. */
    private EventCatalogue $catalogue;

    /**
     * Give the container a catalogue of its own, which a test may define codes
     * in.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::IMPORTED_AT, 'UTC'));

        $this->catalogue = new EventCatalogue;

        app()->instance(EventCatalogue::class, $this->catalogue);
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The record is the line imported: its asserted fields, its source, its id
     * drawn at the import's time, `imported` provenance, and nothing of a
     * credential, guard, session, request, trace or user agent.
     *
     * @return void
     */
    public function testTheRecordIsTheLineImported(): void
    {
        $record = $this->built(self::line());

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertSame(self::CODE, $record->event);
        self::assertSame('denied', $record->outcome);
        self::assertSame('over_limit', $record->reason);
        self::assertSame(['user', '42'], [$record->actorType, $record->actorId]);
        self::assertSame(['invoice', 'inv_0042'], [$record->subjectType, $record->subjectId]);
        self::assertSame(['user', '7'], [$record->principalType, $record->principalId]);
        self::assertSame(['organisation', 'org_01'], [$record->tenantType, $record->tenantId]);
        self::assertSame('app:ticket-123', $record->correlationId);
        self::assertSame(['amount' => '1200.00'], $record->properties);
        self::assertSame(['route' => 'invoices.approve'], $record->context);
        self::assertSame('203.0.113.7', $record->ip);
        self::assertSame('http', $record->origin);
        self::assertSame('2026-10-01T09:00:00.000001Z', $record->occurredAt);
        self::assertSame('imported', $record->provenance);
        $source  = [$record->sourceId, $record->sourceRegion, $record->sourceRecordId, $record->importBatchId, $record->sourceDigest];
        $ambient = [$record->credentialId, $record->guard, $record->sessionId, $record->requestId, $record->traceId, $record->userAgent];

        self::assertSame(['crm-eu', 'eu-west-2', 'rec-0042', self::BATCH, str_repeat('d', 64)], $source);
        self::assertSame([null, null, null, null, null, null], $ambient);
        $time = substr(str_replace('-', '', Str::uuid7(new CarbonImmutable(self::IMPORTED_AT, 'UTC'))->toString()), 0, 12);

        self::assertSame($time, substr(str_replace('-', '', $record->id), 0, 12));
    }

    /**
     * A registered code is built under its definition: its version, its
     * category over the line's, and its field rules.
     *
     * @return void
     */
    public function testARegisteredCodeUsesItsDefinition(): void
    {
        $this->catalogue->define(EventDefinition::for(self::CODE)->version(3)->category('billing')->retain('amount'));

        $record = $this->built(self::line(properties: ['amount' => '1200.00', 'customer' => 'Alice']));

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertSame(3, $record->eventVersion);
        self::assertSame('billing', $record->category);
        self::assertSame(['amount' => '1200.00', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $record->properties);
    }

    /**
     * An unregistered code is built under the default in the line's category,
     * or `general` when the line names none, every field retained.
     *
     * @return void
     */
    public function testAnUnregisteredCodeTakesTheLinesCategory(): void
    {
        $record = $this->built(self::line(properties: ['amount' => '1200.00', 'customer' => 'Alice']));

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertSame('finance', $record->category);
        self::assertSame(1, $record->eventVersion);
        self::assertSame(['amount' => '1200.00', 'customer' => 'Alice'], $record->properties);

        $general = $this->built(self::line(category: null));

        self::assertInstanceOf(AuditRecord::class, $general);
        self::assertSame('general', $general->category);
    }

    /**
     * While registration is required, an unregistered code is
     * `UNREGISTERED_CODE` and a registered one is built.
     *
     * @return void
     */
    public function testUnderRequireRegisteredAnUnregisteredCodeIsRejected(): void
    {
        app(ConfigRepository::class)->set('audit-log.definitions.require_registered', true);

        self::assertSame(ImportRejection::UNREGISTERED_CODE, $this->built(self::line()));

        $this->catalogue->define(EventDefinition::for(self::CODE)->unlisted(FieldHandling::RETAIN));

        self::assertInstanceOf(AuditRecord::class, $this->built(self::line(category: 'billing')));
    }

    /**
     * No contributor runs: a registered one that fills an actor and a guard
     * leaves the record's actor as the line gives it, none, and its guard
     * empty.
     *
     * @return void
     */
    public function testNoContributorRuns(): void
    {
        $registry = new ContributorRegistry;

        $registry->add(ActorFillingContributor::class);

        app()->instance(ContributorRegistry::class, $registry);

        $record = $this->built(self::line(withActor: false));

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertNull($record->actorType);
        self::assertNull($record->actorId);
        self::assertNull($record->guard);
    }

    /**
     * A dry run encrypts nothing: the bound encrypter is never asked, and the
     * field it would seal is dropped and diagnosed, as for an owner with no
     * key; a real build seals it.
     *
     * @return void
     */
    public function testADryRunEncryptsNothing(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        app()->instance(FieldEncrypter::class, $encrypter);

        $this->catalogue->define(EventDefinition::for(self::CODE)->retain('amount')->encrypt('iban', KeyOwner::SUBJECT));

        $planned = $this->built(self::line(properties: ['amount' => '1200.00', 'iban' => 'GB00 0000']), true);

        self::assertInstanceOf(AuditRecord::class, $planned);
        self::assertCount(0, $encrypter->calls());
        self::assertArrayNotHasKey('iban', $planned->properties ?? []);
        self::assertStringNotContainsString('GB00 0000', (string) json_encode($planned->toArray()));

        $built = $this->built(self::line(properties: ['amount' => '1200.00', 'iban' => 'GB00 0000']));

        self::assertInstanceOf(AuditRecord::class, $built);
        self::assertCount(1, $encrypter->calls());
        self::assertSame(['v' => 1, 'k' => 'key_inv_0042', 'c' => base64_encode('"GB00 0000"')], $built->properties['iban'] ?? null);
    }

    /**
     * The imported record's id is drawn at the import's time before the line is
     * minimised, so every value sealed for it is sealed for the entry the
     * record is stored as, with the line's tenant and the definition's
     * category; it is a UUID version 7 of the import's time, never of the time
     * the activity happened.
     *
     * @return void
     */
    public function testTheImportedIdIsMintedBeforeMinimising(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        app()->instance(FieldEncrypter::class, $encrypter);
        app(ConfigRepository::class)->set('audit-log.redaction.ip', 'encrypt');

        $this->catalogue->define(EventDefinition::for(self::CODE)->category('billing')->retain('amount')->encrypt('iban', KeyOwner::SUBJECT));

        $record = $this->built(self::line(properties: ['amount' => '1200.00', 'iban' => 'GB00 0000']));

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertSame([['ip'], ['properties', 'iban']], $encrypter->paths());

        foreach ($encrypter->contexts() as $context) {
            self::assertSame($record->id, $context->entryId);
            self::assertSame(['organisation', 'org_01'], [$context->tenant?->type, $context->tenant?->id]);
            self::assertSame('billing', $context->category);
        }

        self::assertSame('7', $record->id[14]);
        self::assertSame((int) (new CarbonImmutable(self::IMPORTED_AT, 'UTC'))->format('Uv'), hexdec(substr(str_replace('-', '', $record->id), 0, 12)));
    }

    /**
     * A value the builder or the record refuses makes the line `INVALID_FIELD`:
     * a correlation id outside its grammar, and a property under the reserved
     * prefix.
     *
     * @return void
     */
    public function testARefusedValueIsAnInvalidField(): void
    {
        self::assertSame(ImportRejection::INVALID_FIELD, $this->built(self::line(correlationId: 'not namespaced')));
        self::assertSame(ImportRejection::INVALID_FIELD, $this->built(self::line(properties: ['_audit' => ['manifest' => 'x']])));
        self::assertSame(ImportRejection::INVALID_FIELD, $this->built(self::line(origin: 'cron')));
    }

    /**
     * An IP address that is not one is dropped by minimising, as a captured one
     * is, and the record is still built.
     *
     * @return void
     */
    public function testAnIpThatIsNotOneIsDropped(): void
    {
        $record = $this->built(self::line(ip: 'not an address'));

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertNull($record->ip);
    }

    /**
     * A success is built with no reason, and a failure with its reason.
     *
     * @return void
     */
    public function testEachOutcomeIsBuilt(): void
    {
        $success = $this->built(self::line(outcome: Outcome::SUCCESS, reason: null));
        $failure = $this->built(self::line(outcome: Outcome::FAILURE, reason: 'timeout'));

        self::assertInstanceOf(AuditRecord::class, $success);
        self::assertInstanceOf(AuditRecord::class, $failure);
        self::assertSame(['success', null], [$success->outcome, $success->reason]);
        self::assertSame(['failure', 'timeout'], [$failure->outcome, $failure->reason]);
    }

    /**
     * The line's record, from its source, as a dry run or not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function built(ImportLine $line, bool $dryRun = false): AuditRecord|ImportRejection
    {
        $source = new ImportedSource($line->sourceId, $line->sourceRegion, $line->sourceRecordId, self::BATCH, str_repeat('d', 64));

        return app(ImportRecordBuilder::class)->build($line, $source, new CarbonImmutable(self::IMPORTED_AT, 'UTC'), $dryRun);
    }

    /**
     * A line denying an approval, with the parts given.
     *
     * @param  ?array<string, array<string, string>|string>  $properties
     * @param  ?string  $category
     * @param  bool  $withActor
     * @param  string  $correlationId
     * @param  ?string  $origin
     * @param  string  $ip
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(
        ?array $properties = ['amount' => '1200.00'],
        ?string $category = 'finance',
        bool $withActor = true,
        string $correlationId = 'app:ticket-123',
        ?string $origin = 'http',
        string $ip = '203.0.113.7',
        Outcome $outcome = Outcome::DENIED,
        ?string $reason = 'over_limit',
    ): ImportLine {
        return new ImportLine(
            number: 1,
            sourceId: 'crm-eu',
            sourceRegion: 'eu-west-2',
            sourceRecordId: 'rec-0042',
            event: self::CODE,
            occurredAt: '2026-10-01T09:00:00.000001Z',
            outcome: $outcome,
            reason: $reason,
            actor: $withActor ? Reference::of('user', '42') : null,
            subject: Reference::of('invoice', 'inv_0042'),
            principal: Reference::of('user', '7'),
            tenant: Reference::of('organisation', 'org_01'),
            category: $category,
            correlationId: $correlationId,
            properties: $properties,
            context: ['route' => 'invoices.approve'],
            origin: $origin,
            ip: $ip,
        );
    }
}
