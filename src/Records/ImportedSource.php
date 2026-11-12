<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Where an imported record came from, each field checked and never repaired; a
 * refusal names the field, never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportedSource
{
    /** @var int Longest record id at the source, in characters: the `source_record_id` column. */
    public const int SOURCE_RECORD_ID_MAX_CHARACTERS = 191;

    /** @var string A UUID as every engine returns it. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string SHA-256 as lower-case hex. */
    private const string DIGEST_PATTERN = '/\A[0-9a-f]{64}\z/';

    /**
     * Constructor.
     *
     * @param  string  $sourceId
     * @param  ?string  $sourceRegion
     * @param  string  $sourceRecordId
     * @param  string  $importBatchId
     * @param  string  $sourceDigest
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The source that first asserted the record. */
        public string $sourceId,

        /** That source's region, if it named one. */
        public ?string $sourceRegion,

        /** The record's id at that source. */
        public string $sourceRecordId,

        /** The import batch the record comes in. */
        public string $importBatchId,

        /** The keyed digest of the source assertion, lower-case hex. */
        public string $sourceDigest,
    ) {
        self::checkText('source_id', $sourceId, AuditRecord::SOURCE_ID_MAX_CHARACTERS);
        self::checkText('source_region', $sourceRegion, AuditRecord::SOURCE_REGION_MAX_CHARACTERS);
        self::checkText('source_record_id', $sourceRecordId, self::SOURCE_RECORD_ID_MAX_CHARACTERS);
        self::checkPattern('import_batch_id', $importBatchId, self::UUID_PATTERN, 'a lower-case UUID');
        self::checkPattern('source_digest', $sourceDigest, self::DIGEST_PATTERN, '64 lower-case hexadecimal characters');
    }

    /**
     * Refuse a given text field that is empty, too long or not clean text.
     *
     * @param  string  $field
     * @param  ?string  $value
     * @param  int  $maxCharacters
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkText(string $field, ?string $value, int $maxCharacters): void
    {
        if ($value === null || ($value !== '' && mb_strlen($value, 'UTF-8') <= $maxCharacters && TextSanitizer::isClean($value))) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('An imported record\'s `%s` must be from 1 to %d characters, with no control characters.', $field, $maxCharacters));
    }

    /**
     * Refuse a field that does not match its pattern, saying what it must be.
     *
     * @param  string  $field
     * @param  string  $value
     * @param  string  $pattern
     * @param  string  $what
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkPattern(string $field, string $value, string $pattern, string $what): void
    {
        if (preg_match($pattern, $value) === 1) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('An imported record\'s `%s` must be %s.', $field, $what));
    }
}
