<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\FieldPath;

/**
 * Removes every map key longer than a record keeps before anything reads a key;
 * a client-chosen huge key would exhaust memory or fail on MySQL alone.
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
     * counted under the masked path.
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
