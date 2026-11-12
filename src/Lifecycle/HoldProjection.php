<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The holds projection: one row per active hold, an index for listing and
 * `audit-log:check`, never what a prune or a release decides from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HoldProjection
{
    /**
     * Insert the hold's row.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function insert(Connection $connection, #[\SensitiveParameter] Hold $hold): void
    {
        $connection->table(LifecycleTables::holdsTable())->insert(self::rowOf($hold));
    }

    /**
     * Delete the hold's row; a row already missing is no error.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $holdId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function delete(Connection $connection, string $holdId): void
    {
        $connection->table(LifecycleTables::holdsTable())->where('hold_id', $holdId)->delete();
    }

    /**
     * Every row of the projection, by journal sequence.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    public function rows(Connection $connection): array
    {
        $rows = $connection->table(LifecycleTables::holdsTable())->useWritePdo()->orderBy('journal_sequence')->orderBy('hold_id')->get()->all();

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (#[\SensitiveParameter] object $row): array => (array) $row, $rows));
    }

    /**
     * Replace every row with one per hold given, returning the row count.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function rebuild(Connection $connection, #[\SensitiveParameter] array $holds): int
    {
        $connection->table(LifecycleTables::holdsTable())->delete();

        foreach ($holds as $hold) {
            $this->insert($connection, $hold);
        }

        return count($holds);
    }

    /**
     * The sorted ids of holds missing from the rows, rows of no hold, and rows
     * that differ from their hold.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $replayed
     * @param  list<array<string, scalar|null>>  $rows
     * @return list<string>
     *
     * @throws \UnexpectedValueException
     */
    public function drift(#[\SensitiveParameter] array $replayed, #[\SensitiveParameter] array $rows): array
    {
        $expected = [];
        $found    = [];

        foreach ($replayed as $hold) {
            $expected[$hold->id] = self::comparable(self::rowOf($hold));
        }

        foreach ($rows as $row) {
            $found[(string) ($row['hold_id'] ?? '')] = self::comparable($row);
        }

        $drifted = array_keys(array_diff_key($expected, $found) + array_diff_key($found, $expected));

        foreach (array_intersect_key($expected, $found) as $holdId => $comparable) {
            if ($found[$holdId] === $comparable) {
                continue;
            }

            $drifted[] = $holdId;
        }

        $drifted = array_map(strval(...), $drifted);

        sort($drifted, SORT_STRING);

        return $drifted;
    }

    /**
     * The row that projects the hold.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @return array<string, int|string|null>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function rowOf(#[\SensitiveParameter] Hold $hold): array
    {
        $scope = $hold->scope->toArray();

        return [
            'hold_id'            => $hold->id,
            'scope'              => CanonicalEncoder::encode($scope),
            'scope_digest'       => $hold->scope->digest(),
            'basis'              => $hold->basis->value,
            'import_batch_id'    => $scope['import_batch'],
            'placed_at'          => StoredTime::toStorage($hold->placedAt),
            'review_by'          => $hold->reviewBy === null ? null : StoredTime::toStorage($hold->reviewBy),
            'authority_type'     => $hold->operator->type,
            'authority_id'       => $hold->operator->id,
            'reason'             => $hold->reason,
            'external_reference' => $hold->externalReference,
            'operation_id'       => $hold->operationId,
            'journal_sequence'   => $hold->journalSequence,
        ];
    }

    /**
     * What drift compares of a row; an unreadable review date is kept so it
     * never equals a hold's.
     *
     * @param  array<string, scalar|null>  $row
     * @return array{0: ?string, 1: ?string, 2: ?string, 3: ?string}
     */
    private static function comparable(#[\SensitiveParameter] array $row): array
    {
        $reviewBy = $row['review_by'] ?? null;

        try {
            $reviewBy = is_string($reviewBy) ? StoredTime::fromStorage($reviewBy) : $reviewBy;
        } catch (\UnexpectedValueException) {
            $reviewBy = "\0" . $reviewBy;
        }

        return [self::text($row['scope'] ?? null), self::text($row['scope_digest'] ?? null), self::text($row['basis'] ?? null), self::text($reviewBy)];
    }

    /**
     * The value as text, keeping `null`.
     *
     * @param  scalar|null  $value
     * @return ?string
     */
    private static function text(bool|float|int|string|null $value): ?string
    {
        return $value === null ? null : (string) $value;
    }
}
