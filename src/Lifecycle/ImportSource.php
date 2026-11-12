<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * What an import reads: an NDJSON file in one of the import's formats and the
 * source that asserted it.
 *
 * A refusal names the path's problem or the field, never the file's content or
 * the field's value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ImportSource
{
    /**
     * Constructor.
     *
     * @param  string  $path
     * @param  string  $sourceId
     * @param  ?string  $region
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat  $format
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The file the lines are read from. */
        public string $path,

        /** The source that asserted the lines. */
        public string $sourceId,

        /** That source's region, if it names one. */
        public ?string $region,

        /** The format the lines are in. */
        public ImportFormat $format,
    ) {
        self::checkPath($path);
        self::checkText('source id', $sourceId, AuditRecord::SOURCE_ID_MAX_CHARACTERS);

        if ($region === null) {
            return;
        }

        self::checkText('region', $region, AuditRecord::SOURCE_REGION_MAX_CHARACTERS);
    }

    /**
     * A file in the import format, `audit-log-import/v1`, asserted by the
     * source given.
     *
     * @param  string  $path
     * @param  string  $sourceId
     * @param  ?string  $region
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromFile(string $path, string $sourceId, ?string $region = null): self
    {
        return new self($path, $sourceId, $region, ImportFormat::IMPORT_V1);
    }

    /**
     * A file of this package's own `audit-log-export/v1` lines, exported by the
     * source given.
     *
     * @param  string  $path
     * @param  string  $sourceId
     * @param  ?string  $region
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromExport(string $path, string $sourceId, ?string $region = null): self
    {
        return new self($path, $sourceId, $region, ImportFormat::EXPORT_V1);
    }

    /**
     * Refuse a path that is not a readable regular file.
     *
     * @param  string  $path
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkPath(string $path): void
    {
        $problem = match (true) {
            $path === '' || !file_exists($path) => 'does not exist',
            !is_file($path)                     => 'is not a regular file',
            !is_readable($path)                 => 'is not readable',
            default                             => null,
        };

        if ($problem === null) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('The import file `%s` %s.', $path, $problem));
    }

    /**
     * Refuse a text field that is empty, too long or not clean.
     *
     * @param  'region'|'source id'  $field
     * @param  string  $value
     * @param  int  $maxCharacters
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkText(string $field, string $value, int $maxCharacters): void
    {
        if ($value !== '' && mb_strlen($value, 'UTF-8') <= $maxCharacters && TextSanitizer::isClean($value)) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('An import\'s %s must be from 1 to %d characters, with no control characters.', $field, $maxCharacters));
    }
}
