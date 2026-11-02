<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Config\SecretSetting;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;

/**
 * The redaction settings, read from configuration on every call and validated
 * as they are read: the sensitive key names added to the built-ins
 * (`audit-log.redaction.keys`), the key the hashes derive from
 * (`audit-log.redaction.key`, else `app.key`), what is kept of an identifier
 * (`audit-log.redaction.identifiers`) and of an IP address
 * (`audit-log.redaction.ip`), and the two byte budgets
 * (`audit-log.redaction.max_bytes`, `audit-log.redaction.max_context_bytes`).
 *
 * Every malformed value fails closed with an `InvalidArgumentException` naming
 * the setting and never the value, so a malformed explicit key is never
 * replaced by the application key. A missing setting takes its default; a
 * `null` set explicitly is malformed, except for the explicit key, where `null`
 * and an empty value, which an empty environment line gives, read as none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RedactionSettings
{
    /** @var string Prefix of every redaction setting's key. */
    private const string PREFIX = 'audit-log.redaction.';

    /** @var int Greatest value of either byte budget, so a typo cannot disable it. */
    private const int MAX_BUDGET_BYTES = 16777216;

    /** @var string Why `audit-log.redaction.keys` is refused. */
    private const string MALFORMED_KEYS = '`audit-log.redaction.keys` must be a list of key names, each of at least one token.';

    /** @var string Why an `audit-log.redaction.key` that is short or does not decode is refused. */
    private const string MALFORMED_KEY = '`audit-log.redaction.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes.';

    /** @var string Why a missing `app.key` is refused. */
    private const string MISSING_APPLICATION_KEY = '`app.key` must be set to derive the redaction key when `audit-log.redaction.key` is empty.';

    /** @var string Why an `app.key` that is short or does not decode is refused. */
    private const string MALFORMED_APPLICATION_KEY = '`app.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes,'
        . ' to derive the redaction key.';

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
     * The key names configured as sensitive beside the built-ins, each as its
     * tokens, or none when the setting is not set or is empty.
     *
     * @return list<non-empty-list<string>>
     *
     * @throws \InvalidArgumentException
     */
    public function keys(): array
    {
        $keys = $this->config->get(self::PREFIX . 'keys', []);

        if (!is_array($keys) || !array_is_list($keys)) {
            throw new \InvalidArgumentException(self::MALFORMED_KEYS);
        }

        $units = [];

        foreach ($keys as $key) {
            $tokens = is_string($key) ? KeyTokenizer::tokens($key) : [];

            if ($tokens === []) {
                throw new \InvalidArgumentException(self::MALFORMED_KEYS);
            }

            $units[] = $tokens;
        }

        return $units;
    }

    /**
     * The decoded `audit-log.redaction.key`, or `null` when it is not set or is
     * empty.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function explicitKey(): ?string
    {
        $key = $this->config->get(self::PREFIX . 'key');

        if ($key === null || $key === '') {
            return null;
        }

        return SecretSetting::decode($key) ?? throw new \InvalidArgumentException(self::MALFORMED_KEY);
    }

    /**
     * The root secret every hash derives from: the explicit key, or the decoded
     * `app.key` when none is set. A malformed explicit key is refused here too,
     * and never falls back to `app.key`.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function rootKey(): string
    {
        return $this->explicitKey() ?? $this->applicationKey();
    }

    /**
     * What a record keeps of a sign-in identifier.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode
     *
     * @throws \InvalidArgumentException
     */
    public function identifierMode(): IdentifierMode
    {
        $mode = $this->config->get(self::PREFIX . 'identifiers', IdentifierMode::HASH->value);

        return (is_string($mode) ? IdentifierMode::tryFrom($mode) : null)
            ?? throw new \InvalidArgumentException('`audit-log.redaction.identifiers` must be `hash` or `drop`.');
    }

    /**
     * What a record keeps of the client's IP address.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode
     *
     * @throws \InvalidArgumentException
     */
    public function ipMode(): IpMode
    {
        $mode = $this->config->get(self::PREFIX . 'ip', IpMode::FULL->value);

        return (is_string($mode) ? IpMode::tryFrom($mode) : null)
            ?? throw new \InvalidArgumentException('`audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.');
    }

    /**
     * The most bytes the encoded properties of a record may hold, from 8192 to
     * 16777216.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxBytes(): int
    {
        return $this->budget('max_bytes', 16384, 8192);
    }

    /**
     * The most bytes the encoded context of a record may hold, from 1024 to
     * 16777216.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxContextBytes(): int
    {
        return $this->budget('max_context_bytes', 4096, 1024);
    }

    /**
     * Read every redaction setting, failing on the first malformed one. It does
     * not read `app.key`, which is needed only once a hash is.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->keys();
        $this->explicitKey();
        $this->identifierMode();
        $this->ipMode();
        $this->maxBytes();
        $this->maxContextBytes();
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
            throw new \InvalidArgumentException(self::MISSING_APPLICATION_KEY);
        }

        return SecretSetting::decode($key) ?? throw new \InvalidArgumentException(self::MALFORMED_APPLICATION_KEY);
    }

    /**
     * The byte budget under the setting, within its range.
     *
     * @param  string  $setting
     * @param  int  $default
     * @param  int  $least
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function budget(string $setting, int $default, int $least): int
    {
        $key = self::PREFIX . $setting;

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, self::MAX_BUDGET_BYTES);
    }
}
