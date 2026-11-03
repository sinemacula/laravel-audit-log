<?php

declare(strict_types = 1);

namespace Tests\Feature\Export;

use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Export\OcsfFormatter;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use Tests\Fixtures\Export\ApprovedInvoiceMapper;
use Tests\Fixtures\Export\MisclassifyingMapper;
use Tests\Fixtures\Export\OcsfValidator;
use Tests\Fixtures\Export\ReservedKeyMapper;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for the OCSF formatter: a code with no mapping applying is a
 * Base Event that is never classified, a mapped code is classified by its
 * mapper only at its definition's version, both validate offline against the
 * pinned schema, the base attributes and metadata are pinned, the integrity
 * fields are left out, a mapper's attributes are checked, and the line is one
 * line, the same bytes on every call, with every hostile value in its string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OcsfFormatter::class)]
final class OcsfFormatterTest extends TestCase
{
    /** @var string The id every record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The code of every record. */
    private const string CODE = 'invoice.approved';

    /** @var string When every record was recorded. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var string The key id every record is signed with. */
    private const string KEY_ID = 'd03d4735ce37bd961';

    /** @var array<string, int|string> The classification of a Base Event. */
    private const array BASE_EVENT = [
        'activity_id'   => 0,
        'activity_name' => 'Unknown',
        'category_name' => 'Uncategorized',
        'category_uid'  => 0,
        'class_name'    => 'Base Event',
        'class_uid'     => 0,
        'type_name'     => 'Base Event: Unknown',
        'type_uid'      => 0,
    ];

    /**
     * A registered code whose definition names no mapper is a Base Event,
     * unknown activity in no category.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnmappedCodeIsABaseEvent(): void
    {
        $event = $this->event(self::record(), EventDefinition::for(self::CODE)->category('finance'));

        self::assertSame(self::BASE_EVENT, array_intersect_key($event, self::BASE_EVENT));
        self::assertArrayHasKey('unmapped', $event);
    }

    /**
     * A Base Event carries nothing of any class but the base attributes and
     * `unmapped`: no actor, no API, no endpoint, no classification of its own.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnmappedCodeIsNeverClassified(): void
    {
        $event = $this->event(self::record(), EventDefinition::for(self::CODE));

        $expected = [
            'activity_id', 'activity_name', 'category_name', 'category_uid', 'class_name', 'class_uid', 'message', 'metadata',
            'severity', 'severity_id', 'status', 'status_id', 'time', 'type_name', 'type_uid', 'unmapped',
        ];

        self::assertSame($expected, array_keys($event));
    }

    /**
     * A code no definition is registered for, and a code with the package's
     * reserved prefix, which no caller can register, are Base Events.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnregisteredCodeIsABaseEvent(): void
    {
        $unregistered = $this->event(self::record(), EventDefinition::for('invoice.voided')->ocsf(ApprovedInvoiceMapper::class));
        $reserved     = $this->event(self::record(['event' => 'audit_log.exported']), EventDefinition::for(self::CODE)->ocsf(ApprovedInvoiceMapper::class));

        self::assertSame(self::BASE_EVENT, array_intersect_key($unregistered, self::BASE_EVENT));
        self::assertSame(self::BASE_EVENT, array_intersect_key($reserved, self::BASE_EVENT));
        self::assertSame('audit_log.exported', $reserved['message']);
    }

    /**
     * Rows of `[fields]`: records whose Base Events must validate, with every
     * optional column set, and with each left out.
     *
     * @return iterable<string, array{0: array<string, ?string>}>
     */
    public static function provideBaseEventRecords(): iterable
    {
        yield from [
            'a success'             => [[]],
            'a failure'             => [['outcome' => 'failure', 'reason' => 'card_declined']],
            'a denial with no code' => [['outcome' => 'denied']],
            'no optional column'    => [[
                'reason'        => null, 'actor_type' => null, 'actor_id' => null, 'subject_type' => null, 'subject_id' => null,
                'tenant_type'   => null, 'tenant_id' => null, 'guard' => null, 'correlation_id' => null, 'origin' => null,
                'source_region' => null, 'ip' => null, 'user_agent' => null, 'context' => null, 'properties' => null,
            ]],
        ];
    }

    /**
     * A Base Event validates offline against the pinned schema's Base Event,
     * whatever the record holds.
     *
     * @param  array<string, ?string>  $fields
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideBaseEventRecords')]
    public function testABaseEventValidatesAgainstThePinnedSchema(array $fields): void
    {
        $event = $this->event(self::record($fields));

        self::assertSame(0, $event['class_uid']);
        self::assertSame([], OcsfValidator::pinned()->errors($event));
    }

    /**
     * A record its definition's mapper classifies as API Activity validates
     * offline against the pinned schema's API Activity, with the mapper's
     * attributes and the type it gives.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMappedEventValidatesAgainstThePinnedSchema(): void
    {
        $event = $this->event(self::record(), self::mapped());

        self::assertSame([6003, 6, 3, 600303], [$event['class_uid'], $event['category_uid'], $event['activity_id'], $event['type_uid']]);
        self::assertSame(['user' => ['uid' => 'user:42']], $event['actor']);
        self::assertSame(['operation' => self::CODE], $event['api']);
        self::assertSame(['ip' => '203.0.113.7'], $event['src_endpoint']);
        self::assertSame([], OcsfValidator::pinned()->errors($event));
    }

    /**
     * A mapped event has no `type_name`, since the mapper's class supplies no
     * caption, and no `unmapped` of the formatter's.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMappedEventAddsNoNameAndNothingUnmapped(): void
    {
        $event = $this->event(self::record(), self::mapped());

        self::assertArrayNotHasKey('type_name', $event);
        self::assertArrayNotHasKey('unmapped', $event);
    }

    /**
     * The record's id is the event's `metadata.uid`, mapped or not.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheRecordsIdIsAlwaysKept(): void
    {
        self::assertSame(self::ID, self::metadataOf($this->event(self::record()))['uid']);
        self::assertSame(self::ID, self::metadataOf($this->event(self::record(), self::mapped()))['uid']);
    }

    /**
     * The code is the event's `metadata.event_code` and its `message`, mapped
     * or not.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheCodeIsKept(): void
    {
        foreach ([$this->event(self::record()), $this->event(self::record(), self::mapped())] as $event) {
            self::assertSame(self::CODE, self::metadataOf($event)['event_code']);
            self::assertSame(self::CODE, $event['message']);
        }
    }

    /**
     * A mapping applies only to records of its definition's version: a record
     * of version 1 under a definition at version 2 is a Base Event, and one of
     * version 2 is classified.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMappingAppliesOnlyToItsVersion(): void
    {
        $definition = self::mapped()->version(2);

        $older   = $this->event(self::record(), $definition);
        $current = $this->event(self::record(['event_version' => 2]), $definition);

        self::assertSame(self::BASE_EVENT, array_intersect_key($older, self::BASE_EVENT));
        self::assertSame([], OcsfValidator::pinned()->errors($older));
        self::assertSame(6003, $current['class_uid']);
    }

    /**
     * The metadata names the record and its code, the schema version, the
     * product, the time the activity occurred as stored, the time it was
     * recorded in epoch milliseconds, the correlation id and the tenant.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheMetadataIsPinned(): void
    {
        $expected = [
            'correlation_uid' => 'app:ticket-123',
            'event_code'      => self::CODE,
            'logged_time'     => 1793534401654,
            'original_time'   => '2026-11-01T12:00:00.123456Z',
            'product'         => ['name' => 'laravel-audit-log', 'vendor_name' => 'Sine Macula'],
            'tenant_uid'      => 'organisation:org_01',
            'uid'             => self::ID,
            'version'         => '1.9.0',
        ];

        self::assertSame($expected, $this->event(self::record())['metadata']);
        self::assertSame('1.9.0', OcsfFormatter::VERSION);
        self::assertSame(['name' => 'laravel-audit-log', 'vendor_name' => 'Sine Macula'], OcsfFormatter::PRODUCT);
    }

    /**
     * A record with no correlation id and no tenant has neither in its
     * metadata.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testMetadataTheRecordHasNotIsLeftOut(): void
    {
        $metadata = self::metadataOf($this->event(self::record(['correlation_id' => null, 'tenant_type' => null, 'tenant_id' => null])));

        self::assertSame(['event_code', 'logged_time', 'original_time', 'product', 'uid', 'version'], array_keys($metadata));
    }

    /**
     * A tenant missing its type or its id is no tenant: capture never stores
     * one, and a `tenant_uid` must name both.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testATenantMissingAPartIsLeftOut(): void
    {
        self::assertArrayNotHasKey('tenant_uid', self::metadataOf($this->event(self::record(['tenant_type' => null]))));
        self::assertArrayNotHasKey('tenant_uid', self::metadataOf($this->event(self::record(['tenant_id' => null]))));
    }

    /**
     * `time` is when the activity occurred, in whole milliseconds since the
     * Unix epoch, as an integer.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheTimeIsEpochMilliseconds(): void
    {
        self::assertSame(1793534400123, $this->event(self::record())['time']);
        self::assertSame(-1, $this->event(self::record(['occurred_at' => '1969-12-31T23:59:59.999999Z']))['time']);
        self::assertSame(0, $this->event(self::record(['occurred_at' => '1970-01-01T00:00:00.000999Z']))['time']);
        self::assertSame(1793534400999, $this->event(self::record(['occurred_at' => '2026-11-01T12:00:00.999000Z']))['time']);
    }

    /**
     * Rows of `[outcome, reason, the severity and status attributes]`.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: array<string, int|string>}>
     */
    public static function provideOutcomes(): iterable
    {
        yield from [
            'a success' => ['success', null, ['severity' => 'Informational', 'severity_id' => 1, 'status' => 'Success', 'status_id' => 1]],
            'a failure' => ['failure', 'card_declined', [
                'severity'      => 'Medium', 'severity_id' => 3, 'status' => 'Failure', 'status_code' => 'card_declined',
                'status_detail' => 'failure: card_declined', 'status_id' => 2,
            ]],
            'a denial' => ['denied', 'insufficient_role', [
                'severity'      => 'High', 'severity_id' => 4, 'status' => 'Failure', 'status_code' => 'insufficient_role',
                'status_detail' => 'denied: insufficient_role', 'status_id' => 2,
            ]],
            'a denial with no reason' => ['denied', null, ['severity' => 'High', 'severity_id' => 4, 'status' => 'Failure', 'status_detail' => 'denied', 'status_id' => 2]],
        ];
    }

    /**
     * The severity and the status follow the outcome, with the reason as the
     * status code and, with the outcome, as its detail.
     *
     * @param  string  $outcome
     * @param  ?string  $reason
     * @param  array<string, int|string>  $expected
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideOutcomes')]
    public function testTheSeverityAndStatusFollowTheOutcome(string $outcome, ?string $reason, array $expected): void
    {
        $event = $this->event(self::record(['outcome' => $outcome, 'reason' => $reason]));
        $keys  = ['severity', 'severity_id', 'status', 'status_code', 'status_detail', 'status_id'];

        self::assertSame($expected, array_intersect_key($event, array_flip($keys)));
    }

    /**
     * An outcome the record model does not know has no severity, and is refused
     * rather than given one.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesAnUnknownOutcome(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A record\'s outcome must be `success`, `failure` or `denied`.');

        $this->event(self::record(['outcome' => 'partial']));
    }

    /**
     * The HMAC, its key id and the integrity version appear nowhere in the
     * line, mapped or not: a projection is not the integrity artefact.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIntegrityFieldsAreLeftOut(): void
    {
        foreach ([$this->line(self::record()), $this->line(self::record(), self::mapped())] as $line) {
            self::assertStringNotContainsString(self::HMAC, $line);
            self::assertStringNotContainsString(self::KEY_ID, $line);
            self::assertStringNotContainsString('integrity_version', $line);
            self::assertStringNotContainsString('"hmac"', $line);
        }
    }

    /**
     * `unmapped` holds every column with a value that the event does not carry
     * elsewhere, context and properties included, under its stored key; a
     * column with no value is left out.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheUnmappedAttributeHoldsWhatIsNotCarried(): void
    {
        $expected = [
            'actor_id'       => '42',
            'actor_type'     => 'user',
            'category'       => 'finance',
            'context'        => ['method' => 'POST', 'route' => 'invoices.approve'],
            'event_version'  => 1,
            'guard'          => 'web',
            'ip'             => '203.0.113.7',
            'origin'         => 'http',
            'properties'     => ['amount' => '1200.00'],
            'provenance'     => 'captured',
            'record_version' => 1,
            'source_id'      => 'app-eu-1',
            'source_region'  => 'eu-west-2',
            'subject_id'     => 'inv_0042',
            'subject_type'   => 'invoice',
            'user_agent'     => 'Mozilla/5.0',
        ];

        self::assertSame($expected, $this->event(self::record())['unmapped']);
    }

    /**
     * Rows of `[reserved attribute]`: each attribute the formatter sets.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedAttributes(): iterable
    {
        foreach (OcsfFormatter::RESERVED as $reserved) {
            yield $reserved => [$reserved];
        }
    }

    /**
     * A mapper returning an attribute the formatter sets is refused, naming the
     * mapper and the attribute, and the reserved attributes are pinned.
     *
     * @param  string  $reserved
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideReservedAttributes')]
    public function testRefusesAMapperReturningAReservedKey(string $reserved): void
    {
        $this->container()->instance(ReservedKeyMapper::class, new ReservedKeyMapper($reserved));

        self::assertSame(['metadata', 'time', 'severity_id', 'type_uid', 'type_name'], OcsfFormatter::RESERVED);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('The OCSF mapper `%s` returned `%s`, which the formatter sets.', ReservedKeyMapper::class, $reserved));

        $this->event(self::record(), EventDefinition::for(self::CODE)->ocsf(ReservedKeyMapper::class));
    }

    /**
     * Rows of `[classification, the attribute named]`: classifications missing
     * an attribute or giving one as something other than an integer.
     *
     * @return iterable<string, array{0: array<string, int|string>, 1: string}>
     */
    public static function provideIncompleteClassifications(): iterable
    {
        yield from [
            'no class'                => [['category_uid' => 6, 'activity_id' => 3], 'class_uid'],
            'a category as a string'  => [['class_uid' => 6003, 'category_uid' => '6', 'activity_id' => 3], 'category_uid'],
            'no activity'             => [['class_uid' => 6003, 'category_uid' => 6], 'activity_id'],
            'an activity as a string' => [['class_uid' => 6003, 'category_uid' => 6, 'activity_id' => '3'], 'activity_id'],
        ];
    }

    /**
     * A mapper that does not return each of `class_uid`, `category_uid` and
     * `activity_id` as an integer is refused, naming the mapper and the
     * attribute.
     *
     * @param  array<string, int|string>  $classification
     * @param  string  $attribute
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideIncompleteClassifications')]
    public function testRefusesAMapperWithoutAClassification(array $classification, string $attribute): void
    {
        $this->container()->instance(MisclassifyingMapper::class, new MisclassifyingMapper($classification));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('The OCSF mapper `%s` must return `%s` as an integer.', MisclassifyingMapper::class, $attribute));

        $this->event(self::record(), EventDefinition::for(self::CODE)->ocsf(MisclassifyingMapper::class));
    }

    /**
     * A mapper whose class is not in the category it returns is refused, naming
     * the mapper.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesAClassOutsideItsCategory(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('The OCSF mapper `%s` returned a `class_uid` that is not in its `category_uid`.', MisclassifyingMapper::class));

        $this->event(self::record(), EventDefinition::for(self::CODE)->ocsf(MisclassifyingMapper::class));
    }

    /**
     * A class is in its category when its uid is the category's times 1000 plus
     * at most 999, so the last class of a category is accepted.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheLastClassOfACategoryIsInIt(): void
    {
        $this->container()->instance(MisclassifyingMapper::class, new MisclassifyingMapper(['class_uid' => 5999, 'category_uid' => 5, 'activity_id' => 1]));

        $event = $this->event(self::record(), EventDefinition::for(self::CODE)->ocsf(MisclassifyingMapper::class));

        self::assertSame([5999, 5, 599901], [$event['class_uid'], $event['category_uid'], $event['type_uid']]);
    }

    /**
     * A container binding that makes something other than a mapper for the
     * mapper's class is refused rather than called.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRefusesAContainerThatMakesNoMapper(): void
    {
        $this->container()->bind(ApprovedInvoiceMapper::class, static fn (): \stdClass => new \stdClass);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('The container made something other than an `OcsfMapper` for `%s`.', ApprovedInvoiceMapper::class));

        $this->event(self::record(), self::mapped());
    }

    /**
     * The same record gives the same bytes on every call and from every
     * formatter, mapped or not.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRepeatsByteForByte(): void
    {
        self::assertSame($this->line(self::record()), $this->line(self::record()));
        self::assertSame($this->line(self::record(), self::mapped()), $this->line(self::record(), self::mapped()));
    }

    /**
     * The event is one physical line, with no line ending, whatever a value
     * holds, and its keys are sorted at every depth.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsOneLine(): void
    {
        $line = $this->line(self::record(['user_agent' => "a\r\nb", 'properties' => ['note' => "x\ny\u{2028}z"]]));

        foreach (["\r", "\n", "\u{2028}", "\u{2029}"] as $separator) {
            self::assertStringNotContainsString($separator, $line);
        }

        self::assertStringStartsWith('{"activity_id":0,"activity_name":"Unknown","category_name":"Uncategorized",', $line);
    }

    /**
     * A value written to look like JSON, or like an attribute of the event,
     * stays inside its string: the event's classification and metadata are the
     * formatter's, and the value decodes back as it was.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAHostileValueStaysInItsString(): void
    {
        $hostile = '","class_uid":6003,"metadata":{"uid":"forged"},"x":"' . "\"}\n{\"class_uid\":1";
        $event   = $this->event(self::record(['user_agent' => $hostile, 'reason' => 'x', 'outcome' => 'denied', 'properties' => [$hostile => $hostile]]));

        self::assertSame(0, $event['class_uid']);
        self::assertSame(self::ID, self::metadataOf($event)['uid']);
        self::assertIsArray($event['unmapped']);
        self::assertSame($hostile, $event['unmapped']['user_agent']);
        self::assertSame([$hostile => $hostile], $event['unmapped']['properties']);
    }

    /**
     * The mapper is made from the container for every record it classifies, so
     * a binding the application makes is the one used.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMapperIsResolvedFromTheContainer(): void
    {
        $made = 0;

        $this->container()->afterResolving(ApprovedInvoiceMapper::class, static function () use (&$made): void {
            $made++;
        });

        $formatter = $this->formatter(self::mapped());

        $formatter->format(self::finalised(self::record()));
        $formatter->format(self::finalised(self::record()));

        self::assertSame(2, $made);

        $this->container()->instance(MisclassifyingMapper::class, new MisclassifyingMapper(['class_uid' => 6003, 'category_uid' => 6, 'activity_id' => 4]));

        $event = $this->event(self::record(), EventDefinition::for(self::CODE)->ocsf(MisclassifyingMapper::class));

        self::assertSame([6003, 4, 600304], [$event['class_uid'], $event['activity_id'], $event['type_uid']]);
    }

    /**
     * The formatter is made from the container with the application's
     * catalogue, so a code the application registers is classified.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \JsonException
     */
    public function testTheFormatterIsMadeFromTheContainer(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(self::mapped());

        $this->container()->instance(EventCatalogue::class, $catalogue);

        $line = $this->container()->make(OcsfFormatter::class)->format(self::finalised(self::record()));

        self::assertSame(6003, json_decode($line, true, 512, JSON_THROW_ON_ERROR)['class_uid'] ?? null);
    }

    /**
     * The record's parameter is marked sensitive, so a stack trace never holds
     * the record.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(OcsfFormatter::class, 'format'))->getParameters()[0];

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The record as the event the formatter writes, decoded, under a catalogue
     * holding the definitions.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  ...$definitions
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private function event(AuditRecord $record, EventDefinition ...$definitions): array
    {
        $event = json_decode($this->line($record, ...$definitions), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($event);

        return $event;
    }

    /**
     * The record as the line the formatter writes under a catalogue holding the
     * definitions.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  ...$definitions
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function line(AuditRecord $record, EventDefinition ...$definitions): string
    {
        return $this->formatter(...$definitions)->format(self::finalised($record));
    }

    /**
     * A formatter over a catalogue holding the definitions, making mappers from
     * the application's container.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  ...$definitions
     * @return \SineMacula\Laravel\AuditLog\Export\OcsfFormatter
     */
    private function formatter(EventDefinition ...$definitions): OcsfFormatter
    {
        $catalogue = new EventCatalogue;

        foreach ($definitions as $definition) {
            $catalogue->define($definition);
        }

        return new OcsfFormatter($catalogue, $this->container());
    }

    /**
     * The application's container.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function container(): Application
    {
        self::assertNotNull($this->app);

        return $this->app;
    }

    /**
     * The definition of the code that classifies its records as API Activity.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    private static function mapped(): EventDefinition
    {
        return EventDefinition::for(self::CODE)->category('finance')->ocsf(ApprovedInvoiceMapper::class);
    }

    /**
     * The factory's captured record, pinned to the id, with the fields given in
     * place of its own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function record(array $fields = []): AuditRecord
    {
        return RecordFactory::withFields(['id' => self::ID, ...$fields]);
    }

    /**
     * The record finalised, recorded a second after it occurred, or when it
     * occurred if that is later.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function finalised(AuditRecord $record): FinalisedRecord
    {
        return new FinalisedRecord($record, max(self::RECORDED_AT, $record->occurredAt), 1, self::KEY_ID, self::HMAC);
    }

    /**
     * The event's metadata.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $event
     * @return array<array-key, mixed>
     */
    private static function metadataOf(array $event): array
    {
        $metadata = $event['metadata'] ?? null;

        self::assertIsArray($metadata);

        return $metadata;
    }
}
