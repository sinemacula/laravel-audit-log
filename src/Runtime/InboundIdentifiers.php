<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * What an identifier from outside must look like before it is believed: a value
 * from a request header or carried back from a queue payload is the identifier
 * it claims to be, or it is `null`.
 *
 * Each validator takes any value, because a carried value comes back from a
 * payload, and neither cleans nor cuts it. Anything malformed, any non-string
 * included, is `null`, and nothing throws, so the caller falls through without
 * ever having to name what it was given.
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

    /** @var string Pattern of a version-00 `traceparent`: a trace id and a parent id, neither all zero, and the flags, all lower case, capturing the trace id. */
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
     * The trace id of the valid version-00 `traceparent` header the value is,
     * or `null` when it is none.
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
