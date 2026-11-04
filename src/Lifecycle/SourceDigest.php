<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;

/**
 * The keyed digest of an imported line's source assertion, which tells a
 * repeated import of the line from one that conflicts with it.
 *
 * The digest is HMAC-SHA256, as lower-case hex, over the canonical encoding of
 * the assertion, under a key of its own: HKDF-SHA256 over a ring key's secret,
 * with an empty salt and an info string no other key uses, so it is never the
 * key that signs entries, seals or the journal. A new row's digest is taken
 * under the ring's signing key, which then signs the row and names itself in
 * the row's `key_id`; a stored row's is compared under that key. A key the ring
 * no longer holds is an `UnknownKeyException`, and the line is then a conflict,
 * never a duplicate. The assertion is taken before minimisation and encryption,
 * so a definition changed between two imports never changes it. The derived key
 * is never kept.
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
     * The id of the ring's signing key, which a new row's digest is taken
     * under.
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
