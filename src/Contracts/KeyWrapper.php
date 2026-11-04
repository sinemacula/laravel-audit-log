<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Key wrapper contract: the seam that wraps an owner's data key under a
 * wrapping key before the key is stored, and unwraps it when a field sealed
 * under it is read, so a data key is never stored as it is.
 *
 * The package binds `Keys\LocalKeyWrapper`, which wraps with AES-256-GCM under
 * the wrapping keys of `audit-log.privacy.keys`, or under keys derived from
 * `app.key` when none are set. An application rebinds the contract to wrap with
 * an external key service, such as a cloud key management service or a hardware
 * security module. A wrapper whose wrapping keys are held outside the database,
 * and destroyed outside its backups, is how an erasure reaches a backup: a
 * restored wrapped key cannot be unwrapped once the key that wrapped it is
 * gone.
 *
 * The context is the additional data the package builds for each key, naming
 * the key's row, its unit, its generation and the wrapping key, and an
 * implementation must bind it, so a wrapped key moved to another row, or stored
 * beside another wrapping key id, does not unwrap. The wrapped text must be
 * non-empty clean text of at most 65,535 bytes, as it is stored as given.
 * `unwrap()` throws on any failure, a wrapping key it does not hold, a text it
 * did not make and a context that is not the one it was wrapped with among
 * them, and never returns a key it could not authenticate. An implementation
 * must keep no key material between calls, and should mark its own key and
 * wrapped-key parameters `#[\SensitiveParameter]`, since an attribute on this
 * contract does not reach them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface KeyWrapper
{
    /** @var string A wrapping key id: 1 to 191 letters, digits, dots, underscores, colons, slashes or hyphens, starting with a letter or a digit. */
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
