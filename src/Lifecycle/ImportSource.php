<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * What an import reads: a file of NDJSON lines in one of the import's formats,
 * and the source that asserted them, with its region if it names one.
 *
 * `fromFile()` reads the import format, whose every line names it;
 * `fromExport()` reads this package's own export lines, and the source is then
 * the installation that exported them. The path must name a readable regular
 * file when the source is made, the source id is 1 to 64 characters of clean
 * text and the region 1 to 32, each validated, never cleaned or cut. A refusal
 * names the path's problem or the field, never the file's content or the
 * field's value.
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
     * A file of this package's own export lines, `audit-log-export/v1`,
     * exported by the installation given as the source.
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
     * Refuse a path that names nothing, something other than a regular file, or
     * a file this process cannot read.
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
     * Refuse a text field that is empty, longer than its column, or not already
     * clean text.
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
