<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;

/**
 * The keyed digest of an imported line's source assertion, which tells a
 * repeated import from a conflicting one.
 *
 * Its HKDF key is never one that signs and is never kept; the assertion is
 * taken before minimisation, so a changed definition never changes it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SourceDigest
{
    /** @var string HKDF info of every source digest key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:source-digest:v1';

    /** @var int Length of every source digest key, in bytes. */
    private const int KEY_BYTES = 32;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** The ring whose keys the digest keys are derived from. */
        private KeyRing $keys,
    ) {}

    /**
     * The digest of the assertion under the ring key of the id given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $assertion
     * @param  string  $keyId
     * @return string
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \UnexpectedValueException
     */
    public function of(#[\SensitiveParameter] array $assertion, string $keyId): string
    {
        $key = hash_hkdf('sha256', $this->keys->key($keyId)->secret(), self::KEY_BYTES, self::DERIVATION_INFO, '');

        return hash_hmac('sha256', CanonicalEncoder::encode($assertion), $key);
    }

    /**
     * The ring's signing key id, which a new row's digest is taken under.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function signingKeyId(): string
    {
        return $this->keys->signingKey()->id;
    }
}
