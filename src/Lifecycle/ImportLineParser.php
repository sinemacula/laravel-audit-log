<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Support\MachineCode;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * Reads a line of the import format, `audit-log-import/v1`, into an import
 * line, or says why it is rejected.
 *
 * A line is one JSON object, at most 64 levels deep, whose `format` is exactly
 * the format's name; another version of the format is `UNSUPPORTED_VERSION`,
 * and anything else `UNSUPPORTED_FORMAT`. It requires `source_record_id` (1 to
 * 191 characters of clean text), `occurred_at` (an instant in the package's
 * form, no further ahead of the clock than `audit-log.import.max_skew_seconds`),
 * `event` (a code outside the reserved prefix) and `outcome`; it may give
 * `reason` (the grammar of every reason, and only with a failure or a denial),
 * `actor`, `subject`, `principal` and `tenant` (each `{type, id}` or `null`),
 * `category`, `correlation_id`, `properties` and `context` (objects), `origin`
 * (one of this package's origins, or `null` when the source does not know) and
 * `ip`. Any other field is `UNKNOWN_FIELD`, and a field of the wrong type or
 * grammar `INVALID_FIELD`; a property key under the package's reserved
 * `_audit` prefix, at any depth, is refused as the record refuses it.
 *
 * No value shaped as an encrypted envelope is ever imported: every value that
 * is exactly an object of `v`, `k` and `c`, at any depth of the properties and
 * the context, and an IP address that is such an envelope's JSON, is removed
 * and counted, so another system can never plant a value the read path would
 * take for this installation's ciphertext. A decimal is kept as the string the
 * record would store it as, and an integer too large for PHP as its digits.
 *
 * An import whose source is this installation is refused before its file is
 * read; a line is `OWN_SOURCE` here only should that check be bypassed. The
 * export adapter reads its lines' fields through `lineOf()`, so both formats
 * are held to one set of rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportLineParser
{
    /** @var int Deepest JSON a line is decoded to. */
    public const int JSON_DEPTH = 64;

    /** @var list<string> The fields a line must give, in the import format. */
    public const array REQUIRED = ['source_record_id', 'occurred_at', 'event', 'outcome'];

    /** @var list<string> The fields a line may give, in the import format. */
    public const array OPTIONAL = ['reason', 'actor', 'subject', 'principal', 'tenant', 'category', 'correlation_id', 'properties', 'context', 'origin', 'ip'];

    /** @var string The field naming a line's format. */
    private const string FORMAT = 'format';

    /** @var string What every version of the import format's name begins with. */
    private const string FORMAT_FAMILY = 'audit-log-import/';

    /** @var string Prefix of every property key the record reserves for the package's own metadata. */
    private const string RESERVED_KEY = '_audit';

    /** @var list<string> The keys of an encrypted envelope, sorted. */
    private const array ENVELOPE_KEYS = ['c', 'k', 'v'];

    /** @var string Why a field of the wrong type or grammar is refused. */
    private const string INVALID = 'An import line\'s `%s` is not of its type or grammar.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Records\SourceSettings  $sources
     */
    public function __construct(

        /** The settings the skew allowed is read from. */
        private ImportSettings $settings,

        /** The clock a line's occurrence time is held against. */
        private Clock $clock,

        /** The settings this installation's own source is read from. */
        private SourceSettings $sources,
    ) {}

    /**
     * The line of the import format, by its number in the file, as asserted by
     * the import's source, or why it is rejected.
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
        $fields = $source->sourceId === $this->sources->id() ? ImportRejection::OWN_SOURCE : self::formatted($text);

        return $fields instanceof ImportRejection ? $fields : $this->lineOf($number, $fields, $source->sourceId, $source->region);
    }

    /**
     * The line of the fields given under the import format's names, as asserted
     * by the source given, with the count of what was already removed from it,
     * or why it is rejected. The export adapter reads its lines through this
     * once it has mapped their fields.
     *
     * @param  int  $number
     * @param  \stdClass  $fields
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  int  $dropped
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     *
     * @throws \InvalidArgumentException
     */
    public function lineOf(int $number, #[\SensitiveParameter] \stdClass $fields, string $sourceId, ?string $sourceRegion, int $dropped = 0): ImportLine|ImportRejection
    {
        $values   = get_object_vars($fields);
        $rejected = self::fieldRejectionOf($values) ?? $this->timeRejectionOf($values['occurred_at']) ?? self::eventRejectionOf($values['event']);

        if ($rejected !== null) {
            return $rejected;
        }

        try {
            return $this->built($number, $values + array_fill_keys(self::OPTIONAL, null), $sourceId, $sourceRegion, $dropped);
        } catch (\InvalidArgumentException) {
            return ImportRejection::INVALID_FIELD;
        }
    }

    /**
     * Whether the value is exactly an encrypted envelope's shape: an object, or
     * a map, of exactly `v`, `k` and `c`, whatever they hold.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return bool
     */
    public static function isEnvelopeShaped(#[\SensitiveParameter] mixed $value): bool
    {
        $members = $value instanceof \stdClass ? get_object_vars($value) : $value;

        if (!is_array($members) || count($members) !== count(self::ENVELOPE_KEYS)) {
            return false;
        }

        $keys = array_map(strval(...), array_keys($members));

        sort($keys);

        return $keys === self::ENVELOPE_KEYS;
    }

    /**
     * The line built from its values, every optional field among them, once its
     * fields, time and code are known to be acceptable; a value of the wrong
     * type or grammar is refused with an `\InvalidArgumentException`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $number
     * @param  array<string, mixed>  $values
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  int  $dropped
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     *
     * @throws \InvalidArgumentException
     */
    private function built(int $number, #[\SensitiveParameter] array $values, string $sourceId, ?string $sourceRegion, int $dropped): ImportLine
    {
        $outcome    = Outcome::tryFrom(self::string($values['outcome'], 'outcome')) ?? throw new \InvalidArgumentException(sprintf(self::INVALID, 'outcome'));
        $properties = self::mapOf($values['properties'], 'properties', $dropped);
        $context    = self::mapOf($values['context'], 'context', $dropped);
        $ip         = self::ipOf($values['ip'], $dropped);

        if ($properties !== null && self::holdsReservedKey($properties)) {
            throw new \InvalidArgumentException(sprintf('Property keys beginning `%s` are reserved for the package\'s own metadata.', self::RESERVED_KEY));
        }

        return new ImportLine(
            number: $number,
            sourceId: $sourceId,
            sourceRegion: $sourceRegion,
            sourceRecordId: self::recordIdOf($values['source_record_id']),
            event: self::string($values['event'], 'event'),
            occurredAt: self::string($values['occurred_at'], 'occurred_at'),
            outcome: $outcome,
            reason: self::reasonOf($values['reason'], $outcome),
            actor: self::referenceOf($values['actor']),
            subject: self::referenceOf($values['subject']),
            principal: self::referenceOf($values['principal']),
            tenant: self::referenceOf($values['tenant']),
            category: self::codeOf($values['category'], 'category'),
            correlationId: self::nullableString($values['correlation_id'], 'correlation_id'),
            properties: $properties,
            context: $context,
            origin: self::codeOf($values['origin'], 'origin'),
            ip: $ip,
            dropped: $dropped,
        );
    }

    /**
     * Why the line's time is rejected: `INVALID_TIME` for anything but an
     * instant in the package's form, and `FUTURE_TIME` for one further ahead of
     * the clock than the skew allows; `null` when it is accepted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $occurredAt
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection
     *
     * @throws \InvalidArgumentException
     */
    private function timeRejectionOf(mixed $occurredAt): ?ImportRejection
    {
        if (!is_string($occurredAt) || !StoredTime::isInstant($occurredAt)) {
            return ImportRejection::INVALID_TIME;
        }

        $latest = StoredTime::format($this->clock->now()->addSeconds($this->settings->maxSkewSeconds()));

        return strcmp($occurredAt, $latest) > 0 ? ImportRejection::FUTURE_TIME : null;
    }

    /**
     * The JSON object the text holds, without its `format`, once that is the
     * import format's name; or why the line is rejected: `MALFORMED_JSON` for
     * anything but a JSON object, `UNSUPPORTED_VERSION` for another version of
     * the import format, and `UNSUPPORTED_FORMAT` for any other format or none.
     *
     * @param  string  $text
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\stdClass
     */
    private static function formatted(#[\SensitiveParameter] string $text): ImportRejection|\stdClass
    {
        try {
            $fields = json_decode($text, false, self::JSON_DEPTH, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            $fields = null;
        }

        $format    = $fields instanceof \stdClass ? ($fields->{self::FORMAT} ?? null) : null;
        $rejection = match (true) {
            !$fields instanceof \stdClass                                       => ImportRejection::MALFORMED_JSON,
            $format === ImportFormat::IMPORT_V1->value                          => null,
            is_string($format) && str_starts_with($format, self::FORMAT_FAMILY) => ImportRejection::UNSUPPORTED_VERSION,
            default                                                             => ImportRejection::UNSUPPORTED_FORMAT,
        };

        if ($rejection !== null) {
            return $rejection;
        }

        unset($fields->{self::FORMAT});

        return $fields;
    }

    /**
     * Why the line's fields are rejected: `UNKNOWN_FIELD` for one the format
     * does not have, and `MISSING_FIELD` for a required one absent or `null`;
     * `null` when they are acceptable.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $values
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection
     */
    private static function fieldRejectionOf(#[\SensitiveParameter] array $values): ?ImportRejection
    {
        $unknown = array_diff(array_map(strval(...), array_keys($values)), self::REQUIRED, self::OPTIONAL);
        $missing = array_filter(self::REQUIRED, static fn (string $field): bool => ($values[$field] ?? null) === null);

        return match (true) {
            $unknown !== [] => ImportRejection::UNKNOWN_FIELD,
            $missing !== [] => ImportRejection::MISSING_FIELD,
            default         => null,
        };
    }

    /**
     * Why the line's code is rejected: `RESERVED_CODE` for one under the
     * package's reserved prefix, and `INVALID_FIELD` for anything else that is
     * not a code; `null` when it is accepted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $event
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection
     */
    private static function eventRejectionOf(mixed $event): ?ImportRejection
    {
        if (!is_string($event)) {
            return ImportRejection::INVALID_FIELD;
        }

        try {
            EventCode::of($event);
        } catch (\InvalidArgumentException) {
            return str_starts_with($event, EventCode::RESERVED_PREFIX) ? ImportRejection::RESERVED_CODE : ImportRejection::INVALID_FIELD;
        }

        return null;
    }

    /**
     * The record's id at its source: 1 to 191 characters of clean text.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function recordIdOf(mixed $value): string
    {
        $id = self::string($value, 'source_record_id');

        if ($id !== '' && mb_strlen($id, 'UTF-8') <= ImportedSource::SOURCE_RECORD_ID_MAX_CHARACTERS && TextSanitizer::isClean($id)) {
            return $id;
        }

        throw new \InvalidArgumentException(sprintf(self::INVALID, 'source_record_id'));
    }

    /**
     * The reason, in the grammar of every reason, given only with a failure or
     * a denial; `null` when none is given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function reasonOf(mixed $value, Outcome $outcome): ?string
    {
        if ($value === null) {
            return null;
        }

        if ($outcome === Outcome::SUCCESS) {
            throw new \InvalidArgumentException('A success carries no reason.');
        }

        return MachineCode::of(self::string($value, 'reason'), 'A reason');
    }

    /**
     * The reference an object of exactly a type and an id gives, or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function referenceOf(#[\SensitiveParameter] mixed $value): ?Reference
    {
        if ($value === null) {
            return null;
        }

        $parts = $value instanceof \stdClass ? get_object_vars($value) : [];
        $type  = $parts['type'] ?? null;
        $id    = $parts['id']   ?? null;

        if (count($parts) !== 2 || !is_string($type) || !(is_string($id) || is_int($id))) {
            throw new \InvalidArgumentException('A reference is an object of exactly a `type` and an `id`.');
        }

        return Reference::of($type, $id);
    }

    /**
     * The category, a slug of the definitions' grammar, or the origin, one this
     * package names; `null` when it is not given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  'category'|'origin'  $field
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function codeOf(mixed $value, string $field): ?string
    {
        $code  = self::nullableString($value, $field);
        $valid = $code === null || match ($field) {
            'category' => preg_match(EventDefinition::CATEGORY_PATTERN, $code) === 1,
            'origin'   => Origin::tryFrom($code) !== null,
        };

        return $valid ? $code : throw new \InvalidArgumentException(sprintf(self::INVALID, $field));
    }

    /**
     * The object as a map with every envelope-shaped value removed and counted,
     * or `null`; anything but an object is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  'context'|'properties'  $field
     * @param  int  $dropped
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function mapOf(#[\SensitiveParameter] mixed $value, string $field, int &$dropped): ?array
    {
        if ($value !== null && !$value instanceof \stdClass) {
            throw new \InvalidArgumentException(sprintf(self::INVALID, $field));
        }

        if (self::isEnvelopeShaped($value)) {
            $dropped++;

            return null;
        }

        $cleaned = self::cleaned($value, $dropped);

        return is_array($cleaned) ? $cleaned : null;
    }

    /**
     * The value with every envelope-shaped member removed and counted, at any
     * depth: objects as maps, lists as lists, and a decimal as the string the
     * record would store it as.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  int  $dropped
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    private static function cleaned(#[\SensitiveParameter] mixed $value, int &$dropped): mixed
    {
        if (is_float($value)) {
            return ValueNormaliser::float($value);
        }

        if (!$value instanceof \stdClass && !is_array($value)) {
            return $value;
        }

        $members = [];

        foreach ($value instanceof \stdClass ? get_object_vars($value) : $value as $key => $member) {
            if (self::isEnvelopeShaped($member)) {
                $dropped++;

                continue;
            }

            $members[$key] = self::cleaned($member, $dropped);
        }

        return is_array($value) ? array_values($members) : $members;
    }

    /**
     * The IP address as given, or `null`: one that is an envelope's JSON is
     * removed and counted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  int  $dropped
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function ipOf(#[\SensitiveParameter] mixed $value, int &$dropped): ?string
    {
        $ip = self::nullableString($value, 'ip');

        if ($ip === null || !self::isEnvelopeShaped(json_decode(ltrim($ip), false, self::JSON_DEPTH))) {
            return $ip;
        }

        $dropped++;

        return null;
    }

    /**
     * Whether the map holds a key under the reserved prefix, at any depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return bool
     */
    private static function holdsReservedKey(#[\SensitiveParameter] array $values): bool
    {
        foreach ($values as $key => $value) {
            if (str_starts_with((string) $key, self::RESERVED_KEY) || (is_array($value) && self::holdsReservedKey($value))) {
                return true;
            }
        }

        return false;
    }

    /**
     * The value as a string, or `null` for `null`; anything else is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $field
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function nullableString(#[\SensitiveParameter] mixed $value, string $field): ?string
    {
        return $value === null ? null : self::string($value, $field);
    }

    /**
     * The value as a string; anything else is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $field
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function string(#[\SensitiveParameter] mixed $value, string $field): string
    {
        return is_string($value) ? $value : throw new \InvalidArgumentException(sprintf(self::INVALID, $field));
    }
}
