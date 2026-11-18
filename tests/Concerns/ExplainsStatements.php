<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;

/**
 * Asks the engine for the plan of a captured statement, after analysing the
 * tables it reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ExplainsStatements
{
    /**
     * The plan the engine gives the statement, as the text the prefix asks for.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $prefix
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return string
     */
    private static function explain(Connection $connection, string $prefix, array $statement): string
    {
        $text = array_values((array) $connection->selectOne($prefix . $statement['sql'], $statement['bindings']))[0] ?? null;

        self::assertIsString($text);

        return $text;
    }

    /**
     * The decoded and raw JSON plan MySQL or PostgreSQL gives the statement.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array{sql: string, bindings: array<array-key, scalar|null>}  $statement
     * @return array{0: array<array-key, mixed>, 1: string}
     *
     * @throws \JsonException
     */
    private static function jsonExplain(Connection $connection, array $statement): array
    {
        $text = self::explain($connection, $connection->getDriverName() === 'mysql' ? 'EXPLAIN FORMAT=JSON ' : 'EXPLAIN (FORMAT JSON) ', $statement);
        $tree = json_decode($text, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($tree, $text);

        return [$tree, $text];
    }

    /**
     * Analyse the table, so the planner chooses from the rows just stored.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @return void
     */
    private static function analyse(Connection $connection, string $table): void
    {
        $table = $connection->getQueryGrammar()->wrapTable($table);

        match ($connection->getDriverName()) {
            'mysql' => $connection->select('ANALYZE TABLE ' . $table),
            'pgsql' => $connection->statement('ANALYZE ' . $table),
            default => $connection->statement('ANALYZE'),
        };
    }
}
