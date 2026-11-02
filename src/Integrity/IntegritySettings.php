<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Contracts\Config\Repository;

/**
 * The integrity settings, read from configuration on every call and validated
 * as they are read: the explicit ring (`audit-log.integrity.keys`, a map of key
 * ids to secrets), the key that signs (`audit-log.integrity.current`), and the
 * application keys (`app.key`, then `app.previous_keys`) the default ring is
 * derived from when no explicit ring is set.
 *
 * Every secret and application key is its own bytes, or the strict decoding of
 * what follows a `base64:` prefix, and must be at least 32 bytes. Every
 * malformed value fails closed with an `InvalidArgumentException` naming the
 * setting and never the secret, so a malformed explicit ring is never replaced
 * by the derived one. An empty `current`, which an empty environment line
 * gives, reads as none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegritySettings
{
    /** @var string Prefix of every integrity setting's key. */
    private const string PREFIX = 'audit-log.integrity.';

    /** @var string Prefix of a secret or an application key given as base64. */
    private const string BASE64_PREFIX = 'base64:';

    /** @var string Why a current key id or an empty one is refused beside a ring that does not hold it. */
    private const string CURRENT_NOT_IN_RING = '`audit-log.integrity.current` must name a key in `audit-log.integrity.keys`.';

    /** @var string Why a current key id is refused beside an empty ring. */
    private const string CURRENT_WITHOUT_KEYS = '`audit-log.integrity.current` names a key, but `audit-log.integrity.keys` is empty;'
        . ' set both, or neither to derive the key from `app.key`.';

    /** @var string Why an `app.key` that is short or does not decode is refused. */
    private const string MALFORMED_APPLICATION_KEY = '`app.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes,'
        . ' to derive the integrity key.';

    /** @var string Why `app.previous_keys` that are not a list of keys of at least 32 bytes each are refused. */
    private const string MALFORMED_PREVIOUS_KEYS = '`app.previous_keys` must be a list of keys of at least 32 bytes each, or `base64:` followed by the'
        . ' encoding of one, to derive the keys that verify older rows.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The explicit ring: each key id with its decoded secret, or an empty array
     * when `audit-log.integrity.keys` is not set or is empty. A numeric id is
     * the integer key PHP makes of it, so a caller reads every id as a string.
     *
     * @return array<int|string, string>
     *
     * @throws \InvalidArgumentException
     */
    public function explicitKeys(): array
    {
        $keys = $this->config->get(self::PREFIX . 'keys');

        if ($keys === null) {
            return [];
        }

        if (!is_array($keys)) {
            throw new \InvalidArgumentException('`audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.');
        }

        $ring = [];

        foreach ($keys as $id => $secret) {
            $ring[$id] = self::secret((string) $id, $secret);
        }

        return $ring;
    }

    /**
     * The id of the key that signs, validated against the explicit ring: an id
     * in the ring when one is set, and `null` when none is, the key then being
     * derived from `app.key`.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function currentKeyId(): ?string
    {
        $current = $this->config->get(self::PREFIX . 'current');
        $current = $current === '' ? null : $current;

        if ($current !== null && !is_string($current)) {
            throw new \InvalidArgumentException(self::CURRENT_NOT_IN_RING);
        }

        $keys = $this->explicitKeys();

        if ($keys === [] && $current !== null) {
            throw new \InvalidArgumentException(self::CURRENT_WITHOUT_KEYS);
        }

        if ($keys === []) {
            return null;
        }

        if ($current === null || !array_key_exists($current, $keys)) {
            throw new \InvalidArgumentException(self::CURRENT_NOT_IN_RING);
        }

        return $current;
    }

    /**
     * The decoded application keys the default ring is derived from: `app.key`
     * first, then each of `app.previous_keys` in order.
     *
     * @return non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function applicationKeys(): array
    {
        $keys = [$this->applicationKey()];

        $previous = $this->config->get('app.previous_keys') ?? [];

        if (!is_array($previous) || !array_is_list($previous)) {
            throw new \InvalidArgumentException(self::MALFORMED_PREVIOUS_KEYS);
        }

        foreach ($previous as $key) {
            $keys[] = self::decoded($key) ?? throw new \InvalidArgumentException(self::MALFORMED_PREVIOUS_KEYS);
        }

        return $keys;
    }

    /**
     * Read every integrity setting, failing on the first malformed one: the
     * explicit ring and the current key id when a ring is set, otherwise the
     * current key id, `app.key` and `app.previous_keys`. An explicit ring never
     * reads the application keys.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->currentKeyId();

        if ($this->explicitKeys() !== []) {
            return;
        }

        $this->applicationKeys();
    }

    /**
     * The decoded `app.key`.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function applicationKey(): string
    {
        $key = $this->config->get('app.key');

        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('`app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.');
        }

        return self::decoded($key) ?? throw new \InvalidArgumentException(self::MALFORMED_APPLICATION_KEY);
    }

    /**
     * The decoded secret of the explicit key with the id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  mixed  $secret
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function secret(string $id, #[\SensitiveParameter] mixed $secret): string
    {
        if (preg_match(IntegrityKey::ID_PATTERN, $id) !== 1) {
            $message = '`audit-log.integrity.keys` has a key id that is not 1 to 32 letters, digits, dots, underscores'
                . ' or hyphens, starting with a letter or a digit.';

            throw new \InvalidArgumentException($message);
        }

        $decoded = self::decoded($secret);

        if ($decoded === null) {
            throw new \InvalidArgumentException(sprintf('`audit-log.integrity.keys.%s` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.', $id));
        }

        return $decoded;
    }

    /**
     * The bytes of a secret or an application key: the strict decoding of what
     * follows a `base64:` prefix, or the string itself, or `null` when the
     * value is not a string, does not decode, or is shorter than 32 bytes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    private static function decoded(#[\SensitiveParameter] mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $bytes = str_starts_with($value, self::BASE64_PREFIX)
            ? base64_decode(substr($value, strlen(self::BASE64_PREFIX)), true)
            : $value;

        return is_string($bytes) && strlen($bytes) >= IntegrityKey::MIN_SECRET_BYTES ? $bytes : null;
    }
}
