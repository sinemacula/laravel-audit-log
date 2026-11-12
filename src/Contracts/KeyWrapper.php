<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Key wrapper contract: wraps an owner's data key under a wrapping key before
 * it is stored, so a data key is never stored as it is.
 *
 * An implementation binds the context, so a wrapped key unwraps on no other row
 * or wrapping key, never returns a key it could not authenticate, keeps no key
 * material between calls, and should mark its key parameters
 * `#[\SensitiveParameter]`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface KeyWrapper
{
    /** @var string Pattern of a wrapping key id. */
    public const string KEY_ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._:\/-]{0,190}\z/';

    /**
     * The id of the wrapping key a new data key is wrapped under, matching
     * `KEY_ID_PATTERN`.
     *
     * @return string
     *
     * @throws \Throwable
     */
    public function currentKeyId(): string;

    /**
     * The data key wrapped under the wrapping key with the id, bound to the
     * context: non-empty clean text of at most 65,535 bytes.
     *
     * @param  string  $dataKey
     * @param  string  $wrapKeyId
     * @param  string  $context
     * @return string
     *
     * @throws \Throwable
     */
    public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string;

    /**
     * The data key a wrapped text holds, unwrapped under the wrapping key with
     * the id and authenticated against the context; anything else throws.
     *
     * @param  string  $wrapped
     * @param  string  $wrapKeyId
     * @param  string  $context
     * @return string
     *
     * @throws \Throwable
     */
    public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string;
}
