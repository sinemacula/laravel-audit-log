<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Reads the repository's Markdown documentation, by file and by section, for
 * tests that hold the docs to the code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsTheDocumentation
{
    /**
     * The text of the section under the heading, up to the next section.
     *
     * @param  string  $markdown
     * @param  string  $heading
     * @return string
     */
    protected static function section(string $markdown, string $heading): string
    {
        $pattern = '/^## ' . preg_quote($heading, '/') . '\n(.*?)(?=^## |\z)/ms';

        return preg_match($pattern, $markdown, $matches) === 1 ? $matches[1] : '';
    }

    /**
     * The Markdown without fenced code blocks, so a `#` comment is never a
     * heading or a sentence.
     *
     * @param  string  $markdown
     * @return string
     */
    protected static function withoutCodeBlocks(string $markdown): string
    {
        return (string) preg_replace('/^ *(```|~~~)[^\n]*\n.*?^ *\1[ \t]*$/ms', '', $markdown);
    }

    /**
     * The text with whitespace runs collapsed, so a wrapped sentence matches.
     *
     * @param  string  $text
     * @return string
     */
    protected static function collapsed(string $text): string
    {
        return (string) preg_replace('/\s+/', ' ', $text);
    }

    /**
     * Every README configuration row, by key without backticks, as cells.
     *
     * @return array<string, list<string>>
     */
    protected static function configurationRows(): array
    {
        preg_match_all('/^\| `([a-z_.]+)` +\|.*\|$/m', self::readme(), $matches, PREG_SET_ORDER);

        $rows = [];

        foreach ($matches as $match) {
            $rows[$match[1]] = array_map(trim(...), explode('|', trim($match[0], '|')));
        }

        return $rows;
    }

    /**
     * The README.
     *
     * @return string
     */
    protected static function readme(): string
    {
        $readme = file_get_contents(self::root() . '/README.md');

        self::assertIsString($readme);

        return $readme;
    }

    /**
     * A file of the repository, by its path from the root.
     *
     * @param  string  $path
     * @return string
     */
    protected static function read(string $path): string
    {
        $contents = file_get_contents(self::root() . $path);

        self::assertIsString($contents, sprintf('%s cannot be read.', $path));

        return $contents;
    }

    /**
     * The repository's root directory.
     *
     * @return string
     */
    protected static function root(): string
    {
        return dirname(__DIR__, 2);
    }
}
