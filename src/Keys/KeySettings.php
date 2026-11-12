<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Config\SecretSetting;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;

/**
 * The owners' key settings, read and validated on every call; a malformed value
 * fails closed naming the setting, never the secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeySettings
{
    /** @var string Prefix of every owners' key setting's key. */
    private const string PREFIX = 'audit-log.privacy.';

    /** @var array{0: int, 1: int, 2: int} Default, least and greatest number of keys in a rewrap batch. */
    private const array REWRAP_BATCH = [500, 100, 10000];

    /** @var string Refusal for a current key id the ring does not hold. */
    private const string CURRENT_NOT_IN_RING = '`audit-log.privacy.current` must name a key in `audit-log.privacy.keys`.';

    /** @var string Refusal for a current key id beside an empty ring. */
    private const string CURRENT_WITHOUT_KEYS = '`audit-log.privacy.current` names a key, but `audit-log.privacy.keys` is empty;'
        . ' set both, or neither to derive the wrapping key from `app.key`.';

    /** @var string Refusal for a key id outside the grammar. */
    private const string MALFORMED_ID = '`audit-log.privacy.keys` has a key id that is not 1 to 32 letters, digits, dots, underscores or hyphens,'
        . ' starting with a letter or a digit.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegritySettings  $integrity
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,

        /** The integrity settings, which read the application keys. */
        private IntegritySettings $integrity,
    ) {}

    /**
     * The explicit ring's decoded secrets by key id, or empty when unset; PHP
     * makes a numeric id an integer key.
     *
     * @return array<int|string, string>
     *
     * @throws \InvalidArgumentException
     */
    public function explicitKeys(): array
    {
        $keys = $this->config->get(self::PREFIX . 'keys') ?? [];

        if (!is_array($keys)) {
            throw new \InvalidArgumentException('`audit-log.privacy.keys` must be a map of key ids to secrets, or empty to derive the wrapping key from `app.key`.');
        }

        $ids = array_keys($keys);

        return array_combine($ids, array_map(self::secret(...), array_map(strval(...), $ids), $keys));
    }

    /**
     * The id of the key that wraps, or `null` when no explicit ring is set and
     * the key derives from `app.key`.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function currentKeyId(): ?string
    {
        $current = $this->config->get(self::PREFIX . 'current');

        if ($current !== null && !is_string($current)) {
            throw new \InvalidArgumentException(self::CURRENT_NOT_IN_RING);
        }

        $current = $current === '' ? null : $current;
        $keys    = $this->explicitKeys();

        if ($keys === []) {
            return $current === null ? null : throw new \InvalidArgumentException(self::CURRENT_WITHOUT_KEYS);
        }

        return $current !== null && array_key_exists($current, $keys) ? $current : throw new \InvalidArgumentException(self::CURRENT_NOT_IN_RING);
    }

    /**
     * The decoded application keys, `app.key` first, then `app.previous_keys`
     * in order.
     *
     * @return non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function applicationKeys(): array
    {
        return $this->integrity->applicationKeys();
    }

    /**
     * The most keys one batch of a rewrap changes, 100 to 10000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function rewrapBatch(): int
    {
        [$default, $least, $most] = self::REWRAP_BATCH;

        $key = self::PREFIX . 'rewrap_batch';

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }

    /**
     * Read every setting, failing on the first malformed one; an explicit ring
     * never reads the application keys.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        if ($this->currentKeyId() === null) {
            $this->applicationKeys();
        }

        $this->rewrapBatch();
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
        if (preg_match(WrappingKey::ID_PATTERN, $id) !== 1) {
            throw new \InvalidArgumentException(self::MALFORMED_ID);
        }

        $message = sprintf('`audit-log.privacy.keys.%s` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.', $id);

        return SecretSetting::decode($secret) ?? throw new \InvalidArgumentException($message);
    }
}
