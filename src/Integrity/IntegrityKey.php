<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * A key of the integrity ring: the id a row's `key_id` stores, 1 to 32
 * column-safe characters starting with a letter or a digit, and the secret that
 * is the HMAC key itself, at least 32 bytes.
 *
 * The secret is no part of the key's visible state: it is kept wrapped in a
 * `\SensitiveParameterValue`, private, and read through `secret()` alone. A
 * stack trace never shows it, since the constructor marks it sensitive, and
 * neither does a dump (`var_dump()`, `print_r()`, Symfony's dumper behind
 * `dump()` and `dd()`), `json_encode()` or `var_export()`, which show the id
 * and, at most, the empty wrapper.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegrityKey
{
    /** @var string A key id: 1 to 32 column-safe characters. */
    public const string ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\z/';

    /** @var int Shortest secret, in bytes. */
    public const int MIN_SECRET_BYTES = 32;

    /** @var \SensitiveParameterValue The HMAC key, as bytes, wrapped so no dump, encoding or export of the key shows it. */
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

        /** The key's id, as a row's `key_id` stores it; never a secret. */
        public string $id,

        // The HMAC key, as bytes; never shown in a message, a trace or a dump.
        #[\SensitiveParameter]
        string $secret,
    ) {
        if (preg_match(self::ID_PATTERN, $id) !== 1) {
            throw new \InvalidArgumentException('An integrity key id must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        if (strlen($secret) < self::MIN_SECRET_BYTES) {
            throw new \InvalidArgumentException('An integrity key\'s secret must be at least 32 bytes.');
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
     * The HMAC key, as bytes.
     *
     * @return string
     */
    public function secret(): string
    {
        return $this->secret->getValue();
    }
}
