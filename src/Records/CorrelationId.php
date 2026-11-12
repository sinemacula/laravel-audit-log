<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * A correlation id's shape: `<namespace>:<value>`, with a lower-case namespace
 * of up to 32 characters and no control characters.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CorrelationId
{
    /** @var int Longest id, in characters: the `correlation_id` column. */
    public const int MAX_CHARACTERS = 191;

    /** @var string A lower-case namespace, a colon, then a value that starts with a non-space. */
    private const string PATTERN = '/\A[a-z][a-z0-9_-]{0,31}:\S.*\z/u';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether `correlatedWith()` and a correlation filter accept the id.
     *
     * @param  string  $id
     * @return bool
     */
    public static function isValid(string $id): bool
    {
        return mb_strlen($id, 'UTF-8') <= self::MAX_CHARACTERS && TextSanitizer::isClean($id) && preg_match(self::PATTERN, $id) === 1;
    }
}
