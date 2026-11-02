<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The keyed hashes a record keeps in place of a value, in three separate
 * domains: a sign-in identifier, a pseudonymised field and an IP address. Each
 * domain's key is HKDF-SHA256 of the root secret under its own info, so a hash
 * in one domain can never be compared with a hash in another, even under one
 * configured key.
 *
 * A hash is the first 16 hex characters of the domain key's fingerprint, a
 * colon, and the 64 hex characters of the HMAC-SHA256 of the value, 81 bytes in
 * all, so a change of key is visible rather than silently breaking correlation.
 * The key is rebuilt on every call and kept nowhere. A value that can be
 * guessed falls to brute force once the key leaks, so a hash is a pseudonym and
 * not an anonymisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentifierHasher
{
    /** @var string The HKDF info of the key sign-in identifiers are hashed under. */
    public const string IDENTIFIER_INFO = 'sinemacula/audit-log:identifier:v1';

    /** @var string The HKDF info of the key pseudonymised fields are hashed under. */
    public const string FIELD_INFO = 'sinemacula/audit-log:field:v1';

    /** @var string The HKDF info of the key IP addresses are hashed under. */
    public const string IP_INFO = 'sinemacula/audit-log:ip:v1';

    /** @var int How many bytes a domain key holds. */
    private const int KEY_BYTES = 32;

    /** @var string What a domain key's fingerprint is the HMAC of. */
    private const string FINGERPRINT_MESSAGE = 'audit-log:fingerprint';

    /** @var int How many hex characters of the fingerprint a hash keeps. */
    private const int FINGERPRINT_LENGTH = 16;

    /** @var string The shape of a value lower-cased as an email address: one `@`, with no whitespace and something on each side. */
    private const string EMAIL_SHAPE = '/\A[^@\s]+@[^@\s]+\z/u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings  $settings
     */
    public function __construct(

        /** Where the root secret is read from on every call. */
        private RedactionSettings $settings,
    ) {}

    /**
     * The hash of a sign-in identifier, once normalised, or `null` when nothing
     * is left of it. A sign-in form can post a blank identifier, so that is not
     * an error.
     *
     * @param  string  $identifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function identifier(#[\SensitiveParameter] string $identifier): ?string
    {
        $normalised = self::normalised($identifier);

        return $normalised === '' ? null : $this->hash(self::IDENTIFIER_INFO, $normalised);
    }

    /**
     * The hash of a pseudonymised field's complete value, which is never cut: a
     * string once normalised, and anything else as its canonical encoding.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|bool|int|string|null  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function field(#[\SensitiveParameter] array|bool|int|string|null $value): string
    {
        return $this->hash(self::FIELD_INFO, is_string($value) ? self::normalised($value) : CanonicalEncoder::encode($value));
    }

    /**
     * The hash of an IP address in its canonical form, exactly as given.
     *
     * @param  string  $canonicalIp
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function ip(#[\SensitiveParameter] string $canonicalIp): string
    {
        return $this->hash(self::IP_INFO, $canonicalIp);
    }

    /**
     * The value as it is hashed: cleaned and trimmed, and lower-cased when it
     * has the shape of an email address.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function normalised(#[\SensitiveParameter] string $value): string
    {
        $normalised = trim(TextSanitizer::clean($value));

        return preg_match(self::EMAIL_SHAPE, $normalised) === 1 ? mb_strtolower($normalised, 'UTF-8') : $normalised;
    }

    /**
     * The fingerprint of the domain's key and the HMAC of the message under it.
     *
     * @param  string  $info
     * @param  string  $message
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function hash(string $info, #[\SensitiveParameter] string $message): string
    {
        $key = hash_hkdf('sha256', $this->settings->rootKey(), self::KEY_BYTES, $info, '');

        return substr(hash_hmac('sha256', self::FINGERPRINT_MESSAGE, $key), 0, self::FINGERPRINT_LENGTH) . ':' . hash_hmac('sha256', $message, $key);
    }
}
