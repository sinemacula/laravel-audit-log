<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\FieldPath;

/**
 * The longest map key a record keeps, and the values with every longer key's
 * whole branch removed, at every depth, before anything else reads a key.
 *
 * A key can come from whatever filled the map, so a client can choose one. One
 * of a few megabytes would exhaust memory while it is split into tokens,
 * killing the request with a fatal error no failure mode can contain, and one
 * of more than 65,535 bytes that fits a raised budget would be refused by MySQL
 * alone, losing the record on one engine. A key of any length also takes room
 * in a row that only values were meant to take. So nothing past this ceiling is
 * split, stored or measured, and each removal is counted under a path masked
 * whole, `*` in the properties and `context.*` in the context, because a path
 * through such a key says nothing a reader could use. A container left empty
 * stays.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyCeiling
{
    /** @var int Longest map key a record keeps, in bytes. */
    public const int MAX_BYTES = 1024;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the key is longer than a record keeps.
     *
     * @param  string  $key
     * @return bool
     */
    public static function isExceededBy(#[\SensitiveParameter] string $key): bool
    {
        return strlen($key) > self::MAX_BYTES;
    }

    /**
     * The properties with every longer key's branch removed and counted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public static function properties(#[\SensitiveParameter] array $values, OmissionLog $omissions): array
    {
        return self::applied($values, FieldPath::WILDCARD, $omissions);
    }

    /**
     * The context with every longer key's branch removed and counted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    public static function context(#[\SensitiveParameter] array $values, OmissionLog $omissions): array
    {
        return self::applied($values, PathMasker::context([FieldPath::WILDCARD]), $omissions);
    }

    /**
     * The values with every longer key's branch removed, at every depth, each
     * removal counted under the masked path. A list's indexes are never longer,
     * so a list only has its elements walked.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  string  $maskedPath
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    private static function applied(#[\SensitiveParameter] array $values, string $maskedPath, OmissionLog $omissions): array
    {
        foreach ($values as $key => $value) {
            if (self::isExceededBy((string) $key)) {
                unset($values[$key]);

                $omissions->add($maskedPath);
            } elseif (is_array($value)) {
                $values[$key] = self::applied($value, $maskedPath, $omissions);
            }
        }

        return $values;
    }
}
