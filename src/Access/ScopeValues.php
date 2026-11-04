<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Access;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The lists an access scope holds, as it keeps and shows them: references each
 * exact pair once, sorted by type then id bytewise, categories each held to the
 * definitions' grammar, once, sorted bytewise, both refused beyond their
 * limits, and references shown as their type and id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopeValues
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The references, each exact pair once, sorted by type then id bytewise,
     * refused beyond the limit.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @param  int  $limit
     * @param  string  $what
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    public static function references(array $references, int $limit, string $what): array
    {
        $unique = [];

        foreach ($references as $reference) {
            // A part holds no control character, so the NUL keeps the pair
            // apart and sorts it first
            $unique[$reference->type . "\0" . $reference->id] = $reference;
        }

        if (count($unique) > $limit) {
            throw new \InvalidArgumentException(sprintf('An access scope holds at most %d %s.', $limit, $what));
        }

        ksort($unique, SORT_STRING);

        return array_values($unique);
    }

    /**
     * The categories, each held to the definitions' grammar, each once, sorted
     * bytewise, refused beyond the limit.
     *
     * @param  list<string>  $categories
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public static function categoryList(array $categories): array
    {
        foreach ($categories as $category) {
            if (preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
                throw new \InvalidArgumentException('An access scope\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');
            }
        }

        $unique = array_values(array_unique($categories));

        if (count($unique) > AccessScope::MAX_CATEGORIES) {
            throw new \InvalidArgumentException(sprintf('An access scope holds at most %d categories in each list.', AccessScope::MAX_CATEGORIES));
        }

        sort($unique, SORT_STRING);

        return $unique;
    }

    /**
     * Each reference as its type and id, or `null` for no list.
     *
     * @param  ?list<\SineMacula\Laravel\AuditLog\Records\Reference>  $references
     * @return ?list<array{0: string, 1: string}>
     */
    public static function pairs(?array $references): ?array
    {
        return $references === null ? null : array_map(static fn (Reference $reference): array => [$reference->type, $reference->id], $references);
    }
}
