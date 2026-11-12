<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The source id and region, read and validated on every call; every malformed
 * value fails closed, naming the key and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SourceSettings
{
    /** @var string The source id's full key. */
    private const string ID = 'audit-log.source.id';

    /** @var string The source region's full key. */
    private const string REGION = 'audit-log.source.region';

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
     * The id of the source records are captured on, or a slug of the
     * application's name when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function id(): string
    {
        $id = $this->config->get(self::ID);

        if ($id === null || $id === '') {
            return $this->slugOfApplicationName();
        }

        if (!is_string($id) || !self::fits($id, AuditRecord::SOURCE_ID_MAX_CHARACTERS)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be from 1 to %d characters, with no control characters.', self::ID, AuditRecord::SOURCE_ID_MAX_CHARACTERS));
        }

        return $id;
    }

    /**
     * The source's region, or `null` when none is configured.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function region(): ?string
    {
        $region = $this->config->get(self::REGION);

        if ($region === null || $region === '') {
            return null;
        }

        if (!is_string($region) || !self::fits($region, AuditRecord::SOURCE_REGION_MAX_CHARACTERS)) {
            $message = '`%s` must be null or empty, or from 1 to %d characters, with no control characters.';

            throw new \InvalidArgumentException(sprintf($message, self::REGION, AuditRecord::SOURCE_REGION_MAX_CHARACTERS));
        }

        return $region;
    }

    /**
     * Read every source setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->id();
        $this->region();
    }

    /**
     * The ASCII slug of `app.name`, cut to the longest source id with no
     * trailing hyphen.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function slugOfApplicationName(): string
    {
        $name = $this->config->get('app.name');
        $slug = is_string($name) ? rtrim(substr(Str::slug($name), 0, AuditRecord::SOURCE_ID_MAX_CHARACTERS), '-') : '';

        if ($slug === '') {
            throw new \InvalidArgumentException(sprintf('`%s` must be set, because `app.name` gives no slug.', self::ID));
        }

        return $slug;
    }

    /**
     * Whether the text is within the limit and already clean.
     *
     * @param  string  $text
     * @param  int  $maxCharacters
     * @return bool
     */
    private static function fits(string $text, int $maxCharacters): bool
    {
        return mb_strlen($text, 'UTF-8') <= $maxCharacters && TextSanitizer::isClean($text);
    }
}
