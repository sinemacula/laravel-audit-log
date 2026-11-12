<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Stores;

use Monolog\Formatter\LineFormatter;

/**
 * The spill channel the documentation gives, with a path a test chooses, shared
 * by the spill, replay and documentation tests so the tested and documented
 * channels cannot drift.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DocumentedSpillChannel
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The documented channel's configuration, writing to the path.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $path
     * @return array{driver: string, path: string, level: string, permission: int, formatter: class-string<\Monolog\Formatter\LineFormatter>, formatter_with: array{format: string, allowInlineLineBreaks: bool}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function config(string $path): array
    {
        return [
            'driver'         => 'single',
            'path'           => $path,
            'level'          => 'critical',
            'permission'     => 0600,
            'formatter'      => LineFormatter::class,
            'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => false],
        ];
    }
}
