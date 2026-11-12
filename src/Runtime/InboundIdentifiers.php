<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Validates identifiers from request headers or queue payloads: each value is
 * the identifier it claims to be, or `null`, never cleaned, cut or thrown over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InboundIdentifiers
{
    /** @var string Pattern of a request id: 1 to 64 visible ASCII characters. */
    private const string REQUEST_ID_PATTERN = '/\A[\x21-\x7E]{1,64}\z/';

    /** @var string Pattern of a W3C trace id: 32 lower-case hexadecimal digits, not all zero. */
    private const string TRACE_ID_PATTERN = '/\A(?!0{32})[0-9a-f]{32}\z/';

    /** @var string Pattern of a version-00 `traceparent`, capturing its trace id. */
    private const string TRACEPARENT_PATTERN = '/\A00-((?!0{32})[0-9a-f]{32})-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}\z/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The request id the value is, or `null` when it is none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    public static function requestId(mixed $value): ?string
    {
        return is_string($value) && preg_match(self::REQUEST_ID_PATTERN, $value) === 1 ? $value : null;
    }

    /**
     * The W3C trace id the value is, or `null` when it is none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    public static function traceId(mixed $value): ?string
    {
        return is_string($value) && preg_match(self::TRACE_ID_PATTERN, $value) === 1 ? $value : null;
    }

    /**
     * The trace id of the version-00 `traceparent` the value is, or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    public static function traceparent(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        preg_match(self::TRACEPARENT_PATTERN, $value, $matches);

        return $matches[1] ?? null;
    }
}
