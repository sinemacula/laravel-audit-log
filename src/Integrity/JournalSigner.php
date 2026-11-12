<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Signs and verifies lifecycle journal rows under version 1, with a key derived
 * from the ring key's secret by HKDF so a row's HMAC is never an entry's or a
 * seal's signature.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JournalSigner
{
    /** @var string HKDF info of every journal key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:lifecycle:v1';

    /** @var int Length of every journal key, in bytes. */
    private const int JOURNAL_KEY_BYTES = 32;

    /** @var string The HMAC a row is given before it is signed, so its key id can be checked; never stored. */
    private const string UNSIGNED = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyRing  $keys
     */
    public function __construct(

        /** The ring whose signing key signs and whose keys verify. */
        private KeyRing $keys,
    ) {}

    /**
     * The journal key of a ring key's secret, as 32 raw bytes.
     *
     * @param  string  $secret
     * @return string
     */
    public static function key(#[\SensitiveParameter] string $secret): string
    {
        return hash_hkdf('sha256', $secret, self::JOURNAL_KEY_BYTES, self::DERIVATION_INFO, '');
    }

    /**
     * The row signed under the journal key of the ring's signing key, which the
     * row then names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $draft
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function sign(#[\SensitiveParameter] JournalRow $draft): JournalRow
    {
        $key = $this->keys->signingKey();

        // The key id is signed and the HMAC is not, so name the key first
        $named = $draft->withSignature($key->id, self::UNSIGNED);

        return $draft->withSignature($key->id, self::hmac($named, $key));
    }

    /**
     * Whether the row's HMAC is its own, under the key the row names. `false`
     * means only that it does not match; a malformed HMAC and a key the ring
     * does not hold are refused instead.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $signed
     * @return bool
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function verifies(#[\SensitiveParameter] JournalRow $signed): bool
    {
        if (preg_match(SealEnvelope::DIGEST_PATTERN, $signed->hmac) !== 1) {
            throw new \UnexpectedValueException('A journal row\'s `hmac` must be 64 lower-case hexadecimal characters.');
        }

        return hash_equals(self::hmac($signed, $this->keys->key($signed->keyId)), $signed->hmac);
    }

    /**
     * HMAC-SHA256, as lower-case hex, of the row's kind's label and its digest
     * under the journal key of the ring key given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $key
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function hmac(#[\SensitiveParameter] JournalRow $journalRow, #[\SensitiveParameter] IntegrityKey $key): string
    {
        return hash_hmac('sha256', $journalRow->kind->label() . $journalRow->digest(), self::key($key->secret()));
    }
}
