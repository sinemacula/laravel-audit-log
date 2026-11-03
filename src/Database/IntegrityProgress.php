<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;

/**
 * The integrity state table, on the storage connection's writer: the
 * operational progress of sealing, anchoring and verification, one named map of
 * scalars per row, for the health snapshot, for monitoring missed runs and for
 * resuming a sweep.
 *
 * Progress is never evidence: verification reads none of it, and any row may be
 * lost or rewritten without hiding a change to the log. Sealing and anchoring
 * read it only to start where they left off, and fall back to the log itself
 * when it is missing. A row that is missing, or whose value is not a JSON
 * object of scalars, reads as absent, and the next write replaces it. Only the
 * package's own names are read or written, each row is written whole with the
 * time it was written, in UTC to the microsecond, and every statement reads and
 * writes the writer, so a replica's lag never reads as stale progress.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegrityProgress
{
    /** @var string The last seal run: `{at, seals, entries, sweep}`. */
    public const string SEAL_LAST_RUN = 'seal.last_run';

    /** @var string The last seal written: `{sequence, id, sealed_at}`. */
    public const string SEAL_LAST = 'seal.last';

    /** @var string The latest entry time a recent pass has sealed, which only a recent pass moves forward: `{last_recorded_at}`. */
    public const string SEAL_RECENT = 'seal.recent';

    /** @var string Where the sweep resumes: `{recorded_at, id}`. */
    public const string SWEEP_CURSOR = 'sweep.cursor';

    /** @var string The last complete sweep: `{at}`. */
    public const string SWEEP_COMPLETED = 'sweep.completed';

    /** @var string The last seal anchored, and the anchor's name: `{sequence, anchor, anchored_at}`. */
    public const string ANCHOR_LAST = 'anchor.last';

    /** @var string The last anchoring that failed: `{sequence, class, at}`. */
    public const string ANCHOR_LAST_FAILURE = 'anchor.last_failure';

    /** @var string The last complete verification, whether it passed at the strictness it ran at, and that strictness: `{at, head, passed, strict}`. */
    public const string VERIFY_LAST_FULL = 'verify.last_full';

    /** @var list<string> Every name the package reads or writes. */
    private const array NAMES = [
        self::SEAL_LAST_RUN,
        self::SEAL_LAST,
        self::SEAL_RECENT,
        self::SWEEP_CURSOR,
        self::SWEEP_COMPLETED,
        self::ANCHOR_LAST,
        self::ANCHOR_LAST_FAILURE,
        self::VERIFY_LAST_FULL,
    ];

    /** @var string How a time is written: UTC to the microsecond, as every time the package stores. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * The progress under the name, or `null` when there is none or its value is
     * not a JSON object of scalars.
     *
     * @param  string  $name
     * @return ?array<string, scalar|null>
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $name): ?array
    {
        $value   = $this->table($name)->where('name', $name)->value('value');
        $decoded = is_string($value) ? json_decode($value) : null;

        if (!$decoded instanceof \stdClass) {
            return null;
        }

        $fields  = get_object_vars($decoded);
        $scalars = array_filter($fields, static fn (mixed $field): bool => $field === null || is_scalar($field));

        return count($scalars) === count($fields) ? $scalars : null;
    }

    /**
     * Write the progress under the name, replacing any there, as written at the
     * given time.
     *
     * @param  string  $name
     * @param  array<string, scalar|null>  $value
     * @param  \DateTimeInterface  $at
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function put(string $name, array $value, \DateTimeInterface $at): void
    {
        $state = [
            'name'       => $name,
            'value'      => json_encode($value, JSON_FORCE_OBJECT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'updated_at' => \DateTimeImmutable::createFromInterface($at)->setTimezone(new \DateTimeZone('UTC'))->format(self::TIME_FORMAT),
        ];

        $this->table($name)->upsert([$state], ['name'], ['value', 'updated_at']);
    }

    /**
     * Remove the progress under the name, if there is any.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function forget(string $name): void
    {
        $this->table($name)->where('name', $name)->delete();
    }

    /**
     * A query of the state table on the storage connection's writer, once the
     * name is known to be one of the package's own.
     *
     * @param  string  $name
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function table(string $name): Builder
    {
        if (!in_array($name, self::NAMES, true)) {
            throw new \InvalidArgumentException('An integrity progress name must be one of the package\'s own.');
        }

        return $this->database->connection(StorageConnection::name())->table(IntegrityTables::stateTable())->useWritePdo();
    }
}
