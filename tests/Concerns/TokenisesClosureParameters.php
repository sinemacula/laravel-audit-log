<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Reads each closure's parameters out of PHP source by its tokens, so a test
 * can hold every closure in a file to a rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait TokenisesClosureParameters
{
    /**
     * The parameters of each closure in the source, read from its tokens:
     * `function` or `fn` followed straight by a bracket.
     *
     * @param  string  $source
     * @return list<list<string>>
     */
    protected static function closureParametersIn(string $source): array
    {
        $tokens     = self::significantTokens($source);
        $parameters = [];

        foreach ($tokens as $index => $token) {
            if (!is_array($token) || !in_array($token[0], [T_FUNCTION, T_FN], true)) {
                continue;
            }

            $open = self::nextAfter($tokens, $index);

            if (($tokens[$open] ?? null) !== '(') {
                continue;
            }

            $inside = self::argumentsAt($tokens, $open);

            if ($inside === []) {
                continue;
            }

            $parameters[] = $inside;
        }

        return $parameters;
    }

    /**
     * The index of the first token after the index that is not a space.
     *
     * @param  array<int, array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return int
     */
    protected static function nextAfter(array $tokens, int $index): int
    {
        do {
            $index++;
        } while (($tokens[$index] ?? null) === ' ');

        return $index;
    }

    /**
     * The arguments of the bracket opening at the index, split at its top-level
     * commas and trimmed.
     *
     * @param  array<int, array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $open
     * @return list<string>
     */
    protected static function argumentsAt(array $tokens, int $open): array
    {
        $depth     = 1;
        $arguments = [''];
        $count     = count($tokens);

        for ($index = $open + 1; $index < $count; $index++) {
            $text = is_array($tokens[$index]) ? $tokens[$index][1] : $tokens[$index];

            $depth += self::depthChangeOf($text);

            if ($depth === 0) {
                break;
            }

            if ($depth === 1 && $text === ',') {
                $arguments[] = '';

                continue;
            }

            $arguments[array_key_last($arguments)] .= $text;
        }

        return array_values(array_filter(array_map(trim(...), $arguments), static fn (string $argument): bool => $argument !== ''));
    }

    /**
     * What the text does to how many brackets are open.
     *
     * @param  string  $text
     * @return int
     */
    protected static function depthChangeOf(string $text): int
    {
        return match ($text) {
            '(', '[', '#[', '{' => 1,
            ')', ']', '}'       => -1,
            default             => 0,
        };
    }

    /**
     * The source's tokens with its comments gone and each run of whitespace one
     * space, so a list of parameters over many lines reads as one over one.
     *
     * @param  string  $source
     * @return array<int, array{0: int, 1: string, 2: int}|string>
     */
    protected static function significantTokens(string $source): array
    {
        $tokens = [];

        foreach (token_get_all($source) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $tokens[] = is_array($token) && $token[0] === T_WHITESPACE ? ' ' : $token;
        }

        return $tokens;
    }
}
