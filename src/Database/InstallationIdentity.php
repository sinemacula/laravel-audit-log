<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\AuditLog\Support\UuidV7;

/**
 * The installation's id, a UUID v7 under `installation.id` in the integrity
 * state table, written once with a plain insert so the first write wins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InstallationIdentity
{
    /** @var string The state table's row the installation id is kept under. */
    public const string NAME = 'installation.id';

    /** @var string How a time is written: UTC to the microsecond, as every time the package stores. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /** @var string What an installation id must be: a lower-case UUID. */
    private const string ID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string The refusal of a storage connection that reads no installation id. */
    private const string ABSENT = 'The storage connection reaches no installation id; the package\'s migrations seed it, and `audit-log:seal` writes'
        . ' it when it is missing.';

    /** @var string The refusal of a storage connection that reads a malformed installation id. */
    private const string MALFORMED = 'The installation id the storage connection reads is malformed; it is never replaced, so it must be restored.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** Resolves the storage and maintenance connections on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * The installation id through the storage connection's writer, written
     * there first when there is none.
     *
     * @param  \DateTimeInterface  $at
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function ensure(\DateTimeInterface $at): string
    {
        $connection = StorageConnection::resolvedName();
        $value      = $this->valueThrough($connection);

        if ($value === null) {
            $this->insert($connection, $at);

            $value = $this->valueThrough($connection);
        }

        return self::wellFormed($value);
    }

    /**
     * Ensure the installation id, then confirm the maintenance connection reads
     * the same one, so lifecycle writes land beside the entries.
     *
     * @param  \DateTimeInterface  $at
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    public function confirm(\DateTimeInterface $at): void
    {
        $this->confirmAgainst($this->ensure($at));
    }

    /**
     * Confirm both connections read the same well-formed installation id,
     * writing nothing.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    public function check(): void
    {
        $value = $this->valueThrough(StorageConnection::resolvedName()) ?? throw new \UnexpectedValueException(self::ABSENT);

        $this->confirmAgainst(self::wellFormed($value));
    }

    /**
     * The installation id through the connection's writer, or `null` when it is
     * absent or malformed.
     *
     * @param  string  $connection
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function idThrough(string $connection): ?string
    {
        return self::idIn($this->valueThrough($connection));
    }

    /**
     * The state row of a new installation id, a UUID v7 of the given time, as
     * the migration seeds it and `ensure()` writes it.
     *
     * @param  \DateTimeInterface  $at
     * @return array{name: string, value: string, updated_at: string}
     *
     * @throws \JsonException
     */
    public static function row(\DateTimeInterface $at): array
    {
        $instant = \DateTimeImmutable::createFromInterface($at)->setTimezone(new \DateTimeZone('UTC'));

        return [
            'name'       => self::NAME,
            'value'      => json_encode(['id' => UuidV7::at($instant)], JSON_THROW_ON_ERROR),
            'updated_at' => $instant->format(self::TIME_FORMAT),
        ];
    }

    /**
     * Confirm the maintenance connection reads the given id; no read is made
     * when it is the storage connection by name.
     *
     * @param  string  $storage
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    private function confirmAgainst(string $storage): void
    {
        $maintenance = StorageConnection::resolvedMaintenanceName();

        if ($maintenance === StorageConnection::resolvedName()) {
            return;
        }

        $id = $this->idThrough($maintenance);

        if ($id === null) {
            throw InstallationMismatchException::absent();
        }

        if ($id !== $storage) {
            throw InstallationMismatchException::mismatched();
        }
    }

    /**
     * Insert a new installation id; a concurrent first write keeps its own.
     *
     * @param  string  $connection
     * @param  \DateTimeInterface  $at
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function insert(string $connection, \DateTimeInterface $at): void
    {
        try {
            $this->state($connection)->insert(self::row($at));
        } catch (UniqueConstraintViolationException) { // @phpstan-ignore catch.neverThrown
            // A concurrent first write won; the caller reads its id.
        }
    }

    /**
     * The stored value of the installation id's row through the connection's
     * writer, or `null` when there is none.
     *
     * @param  string  $connection
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function valueThrough(string $connection): ?string
    {
        $value = $this->state($connection)->where('name', self::NAME)->value('value');

        return is_string($value) ? $value : null;
    }

    /**
     * A query of the state table on the connection's writer.
     *
     * @param  string  $connection
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function state(string $connection): Builder
    {
        return $this->database->connection($connection)->table(IntegrityTables::stateTable())->useWritePdo();
    }

    /**
     * The id in the stored value, refused as malformed when it holds none.
     *
     * @param  ?string  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function wellFormed(?string $value): string
    {
        return self::idIn($value) ?? throw new \UnexpectedValueException(self::MALFORMED);
    }

    /**
     * The id in a stored value: a JSON object `{id}` holding a lower-case UUID,
     * or `null` for anything else.
     *
     * @param  ?string  $value
     * @return ?string
     */
    private static function idIn(?string $value): ?string
    {
        $decoded = $value === null ? null : json_decode($value);

        if (!$decoded instanceof \stdClass || array_keys(get_object_vars($decoded)) !== ['id']) {
            return null;
        }

        return is_string($decoded->id) && preg_match(self::ID_PATTERN, $decoded->id) === 1 ? $decoded->id : null;
    }
}
