<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;

/**
 * A wrapping ring key; its secret is held in a `\SensitiveParameterValue` so no
 * trace, dump, encoding or export of the key shows it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WrappingKey
{
    /** @var string A wrapping key id of the local ring: 1 to 32 column-safe characters, as an integrity key's. */
    public const string ID_PATTERN = IntegrityKey::ID_PATTERN;

    /** @var int Shortest secret, in bytes. */
    public const int MIN_SECRET_BYTES = 32;

    /** @var \SensitiveParameterValue The wrapping secret, as bytes, wrapped so no dump, encoding or export of the key shows it. */
    private \SensitiveParameterValue $secret;

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $secret
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The key's id, as a key row's `wrap_key_id` stores it; never a secret. */
        public string $id,

        // Kept wrapped in `$this->secret` so no dump or export shows it
        #[\SensitiveParameter]
        string $secret,
    ) {
        if (preg_match(self::ID_PATTERN, $id) !== 1) {
            throw new \InvalidArgumentException('A wrapping key id must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        if (strlen($secret) < self::MIN_SECRET_BYTES) {
            throw new \InvalidArgumentException('A wrapping key\'s secret must be at least 32 bytes.');
        }

        $this->secret = new \SensitiveParameterValue($secret);
    }

    /**
     * What a debug dump shows of the key: its id, never its secret.
     *
     * @return array{id: string}
     */
    public function __debugInfo(): array
    {
        return ['id' => $this->id];
    }

    /**
     * The wrapping secret, as bytes.
     *
     * @return string
     */
    public function secret(): string
    {
        return $this->secret->getValue();
    }
}
