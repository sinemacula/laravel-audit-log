<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

/**
 * An in-memory SQLite PDO that reports the server version it is given, so a
 * connection reads it through the framework's own code, where Laravel strips
 * MariaDB's markers on the `mysql` driver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VersionReportingPdo extends \PDO
{
    /**
     * Constructor.
     *
     * @param  ?string  $version
     */
    public function __construct(

        /** The version the server reports, or `null` for a server that reports none. */
        private readonly ?string $version,
    ) {
        parent::__construct('sqlite::memory:');
    }

    /**
     * The attribute, with the server version the PDO was given.
     *
     * @param  int  $attribute
     * @return ?scalar
     */
    #[\Override]
    public function getAttribute(int $attribute): bool|float|int|string|null
    {
        if ($attribute === \PDO::ATTR_SERVER_VERSION) {
            return $this->version;
        }

        /** @var ?scalar */
        return parent::getAttribute($attribute);
    }
}
