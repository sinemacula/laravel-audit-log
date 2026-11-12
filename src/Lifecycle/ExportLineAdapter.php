<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\RecordVersion;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Reads a line of this package's own `audit-log-export/v1` NDJSON export as
 * another installation's evidence, or says why it is rejected.
 *
 * Envelopes and the exporter's integrity fields are dropped, never treated as
 * this installation's ciphertext or signatures.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExportLineAdapter
{
    /** @var list<string> The columns an exported line must give. */
    private const array REQUIRED = ['id', 'record_version', 'event', 'outcome', 'occurred_at', 'provenance', 'source_id'];

    /** @var list<string> The columns read as the import format's fields of the same name. */
    private const array CARRIED = ['event', 'outcome', 'occurred_at', 'reason', 'category', 'correlation_id', 'context', 'origin', 'ip'];

    /** @var list<string> The references read from their flattened type and id columns. */
    private const array REFERENCES = ['actor', 'subject', 'principal', 'tenant'];

    /** @var string The exporter's own metadata property, removed whole. */
    private const string METADATA_KEY = '_audit';

    /** @var \SineMacula\Laravel\AuditLog\Lifecycle\ImportLineParser Holds the mapped fields to the import format. */
    private ImportLineParser $parser;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Records\SourceSettings  $sources
     */
    public function __construct(

        // Not promoted: only handed to the parser.
        ImportSettings $settings,

        // Not promoted: only handed to the parser.
        Clock $clock,

        /** Gives this installation's own source id. */
        private SourceSettings $sources,
    ) {
        $this->parser = new ImportLineParser($settings, $clock, $sources);
    }

    /**
     * The exported line as an import line, or why it is rejected.
     *
     * @param  int  $number
     * @param  string  $text
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     *
     * @throws \InvalidArgumentException
     */
    public function parse(int $number, #[\SensitiveParameter] string $text, ImportSource $source): ImportLine|ImportRejection
    {
        $values = self::decoded($text);

        if ($values === null) {
            return ImportRejection::MALFORMED_JSON;
        }

        $identity = self::shapeRejectionOf($values) ?? $this->identityOf($values, $source);

        if ($identity instanceof ImportRejection) {
            return $identity;
        }

        [$fields, $dropped] = self::fieldsOf($values, $identity[1]);

        return $this->parser->lineOf($number, $fields, $identity[0], $identity[2], $dropped);
    }

    /**
     * The line's source, its record id there and that source's region, or why
     * the line is rejected.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $values
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @return array{0: string, 1: mixed, 2: ?string}|\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection
     *
     * @throws \InvalidArgumentException
     */
    private function identityOf(#[\SensitiveParameter] array $values, ImportSource $source): array|ImportRejection
    {
        $sourceId = $values['source_id'];
        $region   = $values['source_region'] ?? null;

        if (!is_string($sourceId) || ($region !== null && !is_string($region))) {
            return ImportRejection::INVALID_FIELD;
        }

        return $sourceId === $this->sources->id() ? ImportRejection::OWN_SOURCE : self::provenanceIdentityOf($values, $sourceId, $region, $source);
    }

    /**
     * The identity by provenance: upstream for an imported record, the
     * exporter's, which must be the import's source, for a captured one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $values
     * @param  string  $sourceId
     * @param  ?string  $region
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @return array{0: string, 1: mixed, 2: ?string}|\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection
     */
    private static function provenanceIdentityOf(#[\SensitiveParameter] array $values, string $sourceId, ?string $region, ImportSource $source): array|ImportRejection
    {
        $recordId = $values['source_record_id'] ?? null;

        return match ($values['provenance']) {
            Provenance::IMPORTED->value => $recordId === null ? ImportRejection::MISSING_FIELD : [$sourceId, $recordId, $region],
            Provenance::CAPTURED->value => $sourceId === $source->sourceId ? [$sourceId, $values['id'], $source->region ?? $region] : ImportRejection::SOURCE_MISMATCH,
            default                     => ImportRejection::INVALID_FIELD,
        };
    }

    /**
     * The JSON object the text holds as a map, or `null` for anything else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $text
     * @return ?array<string, mixed>
     */
    private static function decoded(#[\SensitiveParameter] string $text): ?array
    {
        try {
            $line = json_decode($text, false, ImportLineParser::JSON_DEPTH, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            return null;
        }

        return $line instanceof \stdClass ? get_object_vars($line) : null;
    }

    /**
     * Why the line's shape is rejected, or `null` when it is acceptable.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $values
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection
     */
    private static function shapeRejectionOf(#[\SensitiveParameter] array $values): ?ImportRejection
    {
        $version = $values['record_version'] ?? null;
        $unknown = array_diff(array_map(strval(...), array_keys($values)), array_keys(RowCodec::COLUMNS));
        $missing = array_filter(self::REQUIRED, static fn (string $column): bool => ($values[$column] ?? null) === null);

        return match (true) {
            $version === null                                                        => ImportRejection::MISSING_FIELD,
            !is_int($version) || !in_array($version, RecordVersion::SUPPORTED, true) => ImportRejection::UNSUPPORTED_VERSION,
            $unknown !== []                                                          => ImportRejection::UNKNOWN_FIELD,
            $missing !== []                                                          => ImportRejection::MISSING_FIELD,
            default                                                                  => null,
        };
    }

    /**
     * The line's columns as the import format's fields, and how many values
     * were removed; a half-given reference is passed on for the parser to
     * refuse.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $values
     * @param  mixed  $recordId
     * @return array{0: \stdClass, 1: int}
     */
    private static function fieldsOf(#[\SensitiveParameter] array $values, mixed $recordId): array
    {
        $fields   = new \stdClass;
        $dropped  = 0;
        $metadata = self::METADATA_KEY;

        $fields->source_record_id = $recordId;

        foreach (self::CARRIED as $column) {
            $fields->{$column} = $values[$column] ?? null;
        }

        foreach (self::REFERENCES as $reference) {
            $type = $values[$reference . '_type'] ?? null;
            $id   = $values[$reference . '_id']   ?? null;

            $fields->{$reference} = $type === null && $id === null ? null : (object) ['type' => $type, 'id' => $id];
        }

        $properties = $values['properties'] ?? null;

        if ($properties instanceof \stdClass && property_exists($properties, $metadata)) {
            $properties = clone $properties;

            unset($properties->{$metadata});

            $dropped++;
        }

        $fields->properties = $properties;

        return [$fields, $dropped];
    }
}
