<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use Illuminate\Contracts\Config\Repository;

/**
 * The settings under `audit-log.definitions.`, validated on every read; a
 * malformed value fails naming the key, never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DefinitionSettings
{
    /** @var string The setting's full key. */
    private const string REQUIRE_REGISTERED = 'audit-log.definitions.require_registered';

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
     * Whether a code no definition registers is a programming error; off by
     * default.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function requiresRegistered(): bool
    {
        $required = $this->config->get(self::REQUIRE_REGISTERED, false);

        if (!is_bool($required)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be true or false.', self::REQUIRE_REGISTERED));
        }

        return $required;
    }

    /**
     * Read every definition setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->requiresRegistered();
    }
}
