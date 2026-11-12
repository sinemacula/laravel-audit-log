<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The retention policy the package binds, read from configuration with 0
 * meaning forever; the tenant is never consulted.
 *
 * The version is unkeyed so a rotation of the integrity ring does not journal a
 * policy that is not new.
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

    /** @var int Hexadecimal characters of the settings' digest a version keeps. */
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
     * The days the category's entries are kept, falling back to `after_days`,
     * or `null` for forever.
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
     * The days the category's entries must stay readable: `null` for none and
     * `PHP_INT_MAX` for forever.
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
     * The canonical settings the version digests, which the journal records
     * with the policy.
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
