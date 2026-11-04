<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;

/**
 * The read and export settings, read from configuration on every call and
 * validated as they are read: the most entries a page of the trail may ask for
 * (`audit-log.read.max_per_page`) and how many entries an export reads per
 * statement (`audit-log.export.chunk`).
 *
 * A missing setting takes its default; a `null` set explicitly is malformed. A
 * number is an integer, or the canonical digit string an environment line
 * gives, within its range. Every malformed value fails closed with an
 * `InvalidArgumentException` naming the key and never the value, so a read or
 * an export never runs on a size nobody chose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadSettings
{
    /** @var string Prefix of every read and export setting's key. */
    private const string PREFIX = 'audit-log.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting, by its key under the prefix. */
    private const array NUMBERS = [
        'read.max_per_page' => [100, 1, 500],
        'export.chunk'      => [1000, 100, 10000],
    ];

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
     * The most entries a page of the trail may ask for, from 1 to 500.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxPerPage(): int
    {
        return $this->number('read.max_per_page');
    }

    /**
     * How many entries an export reads per statement, from 100 to 10000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function exportChunk(): int
    {
        return $this->number('export.chunk');
    }

    /**
     * Read every read and export setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->maxPerPage();
        $this->exportChunk();
    }

    /**
     * The numeric setting under the key, within its range.
     *
     * @param  key-of<self::NUMBERS>  $setting
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $setting): int
    {
        [$default, $least, $most] = self::NUMBERS[$setting];

        $key = self::PREFIX . $setting;

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }
}
