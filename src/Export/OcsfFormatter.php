<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Export;

use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Projects a finalised record as one OCSF event of version 1.9.0 of the Open
 * Cybersecurity Schema Framework, in canonical JSON on one line.
 *
 * Every event carries `time` (when the activity occurred, in epoch
 * milliseconds), `severity_id` and `severity` (1 Informational for a success, 3
 * Medium for a failure, 4 High for a denial), `status_id` and `status` (1
 * Success, or 2 Failure with the outcome and any reason in `status_detail`),
 * the reason in `status_code`, the event code as `message`, `type_uid`, and
 * `metadata`: the record's id as `uid`, the code as `event_code`, the schema
 * version, the product, the time the activity occurred as stored, the time it
 * was recorded, and the correlation id and tenant when the record has them.
 *
 * A code is classified only by the mapper its definition names, and only for
 * records of the definition's version; the mapper's attributes are checked
 * before they are added. Any other record is a Base Event, unknown activity in
 * no category, whose `unmapped` attribute holds every column with a value that
 * is not carried elsewhere, so a classification is never invented and nothing
 * the record says is lost. The HMAC, its key id and the integrity version are
 * left out: the event is a projection, never the integrity artefact. The same
 * record always gives the same bytes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OcsfFormatter implements AuditFormatter
{
    /** @var string The version of OCSF every event is in. */
    public const string VERSION = '1.9.0';

    /** @var list<string> The attributes the formatter sets, which a mapper may not return. */
    public const array RESERVED = ['metadata', 'time', 'severity_id', 'type_uid', 'type_name'];

    /** @var list<string> The integer attributes a mapper must return to classify a record. */
    public const array CLASSIFICATION = ['class_uid', 'category_uid', 'activity_id'];

    /** @var array<string, string> The product every event names in its metadata. */
    public const array PRODUCT = ['name' => 'laravel-audit-log', 'vendor_name' => 'Sine Macula'];

    /** @var array<string, array{0: int, 1: string}> The severity id and its caption for each outcome. */
    private const array SEVERITIES = ['success' => [1, 'Informational'], 'failure' => [3, 'Medium'], 'denied' => [4, 'High']];

    /** @var array<string, int|string> The classification of a record no mapper classifies: a Base Event of unknown activity, in no category. */
    private const array BASE_EVENT = [
        'class_uid'     => 0,
        'class_name'    => 'Base Event',
        'category_uid'  => 0,
        'category_name' => 'Uncategorized',
        'activity_id'   => 0,
        'activity_name' => 'Unknown',
        'type_uid'      => 0,
        'type_name'     => 'Base Event: Unknown',
    ];

    /** @var list<string> The columns a Base Event carries outside `unmapped`, or leaves out because they are the integrity artefact's. */
    private const array CARRIED = [
        'id', 'event', 'outcome', 'reason', 'correlation_id', 'tenant_type', 'tenant_id', 'occurred_at', 'recorded_at',
        'integrity_version', 'key_id', 'hmac',
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue  $catalogue
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The catalogue whose definitions name the mappers. */
        private EventCatalogue $catalogue,

        /** The container each record's mapper is made from. */
        private ContainerContract $container,
    ) {}

    /**
     * The record as one OCSF event: classified by its definition's mapper when
     * one applies, and a Base Event otherwise.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function format(#[\SensitiveParameter] FinalisedRecord $record): string
    {
        $mapper = $this->mapperFor($record->record);

        $classified = $mapper === null
            ? [...self::BASE_EVENT, 'unmapped' => self::unmapped($record)]
            : self::checked($mapper, $mapper->map($record));

        return CanonicalEncoder::encode([...self::base($record), ...$classified]);
    }

    /**
     * The mapper that classifies the record: the one its code's registered
     * definition names, made from the container, when the record is of the
     * definition's version; otherwise `null`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Contracts\OcsfMapper
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \UnexpectedValueException
     */
    private function mapperFor(#[\SensitiveParameter] AuditRecord $record): ?OcsfMapper
    {
        $definition = $this->definitionOf($record->event);

        if ($definition?->ocsfMapper === null || $definition->version !== $record->eventVersion) {
            return null;
        }

        return self::asMapper($this->container->make($definition->ocsfMapper), $definition->ocsfMapper);
    }

    /**
     * The registered definition of the code, the package's own codes' included,
     * or `null` when the code has none or is not a code at all.
     *
     * @param  string  $code
     * @return ?\SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    private function definitionOf(string $code): ?EventDefinition
    {
        try {
            $eventCode = EventCode::forReading($code);

            return $this->catalogue->isRegistered($eventCode) ? $this->catalogue->definitionFor($eventCode) : null;
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * What the container made for the mapper's class, refused unless it is a
     * mapper.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $made
     * @param  string  $class
     * @return \SineMacula\Laravel\AuditLog\Contracts\OcsfMapper
     *
     * @throws \UnexpectedValueException
     */
    private static function asMapper(mixed $made, string $class): OcsfMapper
    {
        return $made instanceof OcsfMapper ? $made : throw new \UnexpectedValueException(sprintf('The container made something other than an `OcsfMapper` for `%s`.', $class));
    }

    /**
     * The attributes every event carries, whatever its class.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<string, array<string, string>|int|string>|int|string>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function base(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        $captured = $record->record;

        [$severityId, $severity] = self::severityOf($captured->outcome);

        return [
            'time'        => self::epochMilliseconds($captured->occurredAt),
            'severity_id' => $severityId,
            'severity'    => $severity,
            ...self::status($captured->outcome, $captured->reason),
            'message'  => $captured->event,
            'metadata' => self::metadata($record),
        ];
    }

    /**
     * The severity id of the outcome and its caption.
     *
     * @param  string  $outcome
     * @return array{0: int, 1: string}
     *
     * @throws \UnexpectedValueException
     */
    private static function severityOf(string $outcome): array
    {
        return self::SEVERITIES[$outcome] ?? throw new \UnexpectedValueException('A record\'s outcome must be `success`, `failure` or `denied`.');
    }

    /**
     * The status of the outcome: 1 Success, or 2 Failure with the outcome and
     * any reason in its detail; and the reason, when there is one, as its code.
     *
     * @param  string  $outcome
     * @param  ?string  $reason
     * @return array<string, int|string>
     */
    private static function status(string $outcome, ?string $reason): array
    {
        $detail = $reason  === null ? $outcome : $outcome . ': ' . $reason;
        $status = $outcome === Outcome::SUCCESS->value
            ? ['status_id' => 1, 'status' => 'Success']
            : ['status_id' => 2, 'status' => 'Failure', 'status_detail' => $detail];

        return $reason === null ? $status : [...$status, 'status_code' => $reason];
    }

    /**
     * The event's metadata: the record's id and code, the schema version and
     * the product, both times, and the correlation id and tenant when the
     * record has them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<string, string>|int|string>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function metadata(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        $captured = $record->record;

        $metadata = [
            'uid'             => $captured->id,
            'event_code'      => $captured->event,
            'version'         => self::VERSION,
            'product'         => self::PRODUCT,
            'original_time'   => $captured->occurredAt,
            'logged_time'     => self::epochMilliseconds($record->recordedAt),
            'correlation_uid' => $captured->correlationId,
            'tenant_uid'      => $captured->tenantType === null || $captured->tenantId === null ? null : $captured->tenantType . ':' . $captured->tenantId,
        ];

        return array_filter($metadata, static fn (array|int|string|null $value): bool => $value !== null);
    }

    /**
     * Every column of the record with a value that the event does not carry
     * elsewhere and that is not the integrity artefact's, by its stored key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return \stdClass
     */
    private static function unmapped(#[\SensitiveParameter] FinalisedRecord $record): \stdClass
    {
        $unmapped = [];

        foreach ($record->toArray() as $column => $value) {
            if ($value === null || in_array($column, self::CARRIED, true)) {
                continue;
            }

            $unmapped[$column] = $value;
        }

        return (object) $unmapped;
    }

    /**
     * The mapper's attributes once checked, with the type they give: none of
     * the reserved attributes, and an integer class, category and activity,
     * with the class in the category.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\OcsfMapper  $mapper
     * @param  array<string, array<array-key, mixed>|bool|int|string|null>  $attributes
     * @return array<string, array<array-key, mixed>|bool|int|string|null>
     *
     * @throws \UnexpectedValueException
     */
    private static function checked(OcsfMapper $mapper, #[\SensitiveParameter] array $attributes): array
    {
        $name = get_debug_type($mapper);

        foreach (self::RESERVED as $reserved) {
            if (array_key_exists($reserved, $attributes)) {
                throw new \UnexpectedValueException(sprintf('The OCSF mapper `%s` returned `%s`, which the formatter sets.', $name, $reserved));
            }
        }

        [$class, $category, $activity] = array_map(static fn (string $key): int => self::integer($name, $attributes, $key), self::CLASSIFICATION);

        if (intdiv($class, 1000) !== $category) {
            throw new \UnexpectedValueException(sprintf('The OCSF mapper `%s` returned a `class_uid` that is not in its `category_uid`.', $name));
        }

        return [...$attributes, 'type_uid' => $class * 100 + $activity];
    }

    /**
     * The integer the mapper returned under the key, which is required.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $mapper
     * @param  array<string, array<array-key, mixed>|bool|int|string|null>  $attributes
     * @param  string  $key
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    private static function integer(string $mapper, #[\SensitiveParameter] array $attributes, string $key): int
    {
        $value = $attributes[$key] ?? null;

        return is_int($value) ? $value : throw new \UnexpectedValueException(sprintf('The OCSF mapper `%s` must return `%s` as an integer.', $mapper, $key));
    }

    /**
     * The instant, in the package's form, in milliseconds since the Unix epoch.
     *
     * @param  string  $instant
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function epochMilliseconds(string $instant): int
    {
        $parsed = StoredTime::instant(StoredTime::toStorage($instant));

        return $parsed->getTimestamp() * 1000 + intdiv((int) $parsed->format('u'), 1000);
    }
}
