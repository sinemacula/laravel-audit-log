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
 * Reads a line of this package's own NDJSON export, `audit-log-export/v1`, as
 * another installation's evidence: into an import line, or says why it is
 * rejected.
 *
 * A line is the envelope the exporting installation stored, under the entries
 * table's column names, of a record version this package reads, else
 * `UNSUPPORTED_VERSION`; a column the version does not have is `UNKNOWN_FIELD`.
 * A record that installation captured is asserted by it: its `source_id` must
 * be the import's source (`SOURCE_MISMATCH`), and its `id` is the record's id
 * there. A record it had itself imported keeps its upstream identity, the
 * `source_id`, `source_record_id` and region it was imported under, so it is
 * never mistaken for that installation's own. A record whose source, either
 * way, is this installation is `OWN_SOURCE`: this installation's own records
 * come back through `audit-log:replay`, never as foreign evidence.
 *
 * The references are read from their flattened columns, and the remaining
 * fields from theirs, held to the import format's rules, a reserved code
 * included (`RESERVED_CODE`). `properties._audit` is removed whole and counted,
 * since its manifest descriptor names an artifact that is not imported and its
 * note, hash and diagnostics are the exporter's own; every value shaped as an
 * encrypted envelope, at any depth of the properties and the context, and an IP
 * address that is an envelope's JSON, is removed and counted, never treated as
 * this installation's ciphertext nor encrypted again. The integrity fields
 * (`recorded_at`, `integrity_version`, `key_id`, `hmac`) are another ring's and
 * are ignored, as are the exporter's credential, guard, session, request, trace
 * and user agent, its event version, batch and digest.
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

    /** @var string The property removed whole: the exporter's own metadata. */
    private const string METADATA_KEY = '_audit';

    /** @var \SineMacula\Laravel\AuditLog\Lifecycle\ImportLineParser The parser the mapped fields are read through, held to the import format's rules. */
    private ImportLineParser $parser;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Records\SourceSettings  $sources
     */
    public function __construct(

        // The settings the skew allowed is read from.
        ImportSettings $settings,

        // The clock a line's occurrence time is held against.
        Clock $clock,

        /** The settings this installation's own source is read from. */
        private SourceSettings $sources,
    ) {
        $this->parser = new ImportLineParser($settings, $clock, $sources);
    }

    /**
     * The exported line, by its number in the file, as evidence of the import's
     * source, or why it is rejected.
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
     * The line's source, its record id there and that source's region: the
     * exporter's for a record it captured, which must be the import's source,
     * and the upstream one for a record it imported; or why the line is
     * rejected.
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
     * The identity of a line from another installation, by its provenance: the
     * upstream source and record id of a record it imported, and its own
     * source, which must be the import's, and its record's id for a record it
     * captured; or why the line is rejected.
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
     * The JSON object the text holds as a map of its columns, or `null` when it
     * holds anything else or is not JSON at all.
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
     * Why the line's shape is rejected: `UNSUPPORTED_VERSION` for a record
     * version this package does not read, `UNKNOWN_FIELD` for a column the
     * version does not have, and `MISSING_FIELD` for a required one absent or
     * `null`; `null` when the shape is acceptable.
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
     * The line's columns as the import format's fields, with its record id
     * there, and how many values were removed: `properties._audit`, whole. A
     * reference half given is passed on as it is, and refused.
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
