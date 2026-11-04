<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The retention policy the package binds: the configured days of each category,
 * `audit-log.retention.after_days` for a category with none of its own, and the
 * configured preservation of each category, with 0 meaning forever in each. The
 * tenant is never consulted.
 *
 * Its version is `config:` and the first 16 hexadecimal characters of the
 * SHA-256 of its canonical settings, so it changes exactly when the settings
 * do. It is not keyed: the settings are not secret, and a fingerprint under the
 * integrity ring would change with every rotation of the ring and journal a
 * policy that is not new. Every answer validates every retention setting first,
 * so a malformed one, or a category kept for less than it is preserved, prunes
 * nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredRetentionPolicy implements RetentionPolicy
{
    /** @var string What every version of the configured policy starts with. */
    public const string VERSION_PREFIX = 'config:';

    /** @var int How many hexadecimal characters of the settings' digest a version keeps. */
    private const int VERSION_DIGEST_CHARACTERS = 16;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings  $settings
     */
    public function __construct(

        /** The retention settings, read on every answer. */
        private RetentionSettings $settings,
    ) {}

    /**
     * The policy's version: `config:` and the first 16 hexadecimal characters
     * of the SHA-256 of its canonical settings.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function version(): string
    {
        return self::VERSION_PREFIX . substr(hash('sha256', CanonicalEncoder::encode($this->settings())), 0, self::VERSION_DIGEST_CHARACTERS);
    }

    /**
     * The days the category's entries are kept: its own, else
     * `audit-log.retention.after_days`, and `null` for forever when that is 0.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function retainFor(string $category, ?Reference $tenant): ?int
    {
        $this->settings->validate();

        $days = $this->settings->categories()[$category] ?? $this->settings->afterDays();

        return $days === 0 ? null : $days;
    }

    /**
     * The days the category's entries must stay readable: `null` when the
     * category has no preservation, and `PHP_INT_MAX` for forever when it is 0.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function preserveFor(string $category, ?Reference $tenant): ?int
    {
        $this->settings->validate();

        $days = $this->settings->preserve()[$category] ?? null;

        return $days === 0 ? PHP_INT_MAX : $days;
    }

    /**
     * The canonical settings the version is the digest of, which the journal
     * records with the policy: the default days and each map of days, sorted
     * bytewise by category.
     *
     * @return array{after_days: int, categories: array<string, int>, preserve: array<string, int>}
     *
     * @throws \InvalidArgumentException
     */
    public function settings(): array
    {
        $this->settings->validate();

        return [
            'after_days' => $this->settings->afterDays(),
            'categories' => $this->settings->categories(),
            'preserve'   => $this->settings->preserve(),
        ];
    }
}
