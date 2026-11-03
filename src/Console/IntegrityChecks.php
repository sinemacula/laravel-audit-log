<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;

/**
 * The integrity checks of `audit-log:check`, beyond a key that signs: the
 * checkpoints, checkpoint members and integrity state tables have the shipped
 * shape on the storage connection, and the disk a disk anchor writes to is
 * configured.
 *
 * The three tables are checked as `SchemaChecks` checks any of the package's
 * tables, each named by its label. A storage connection that is not configured
 * or cannot be opened is left to the `schema` subject, which reports it, and a
 * statement that fails is named by its class. With the `disk` driver, the disk
 * must be configured in `filesystems.disks`; the disk itself is never resolved,
 * read or written, so a check never leaves an object behind. The checks read
 * configuration and the tables' schema; they write nothing and print no
 * setting's value beyond the name of a connection or a disk.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegrityChecks
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The configuration the settings and the disks are read from. */
        private ConfigRepository $config,

        /** The connections the integrity tables are read on. */
        private DatabaseManager $database,
    ) {}

    /**
     * Every integrity problem: those of the three integrity tables, then the
     * anchor disk's.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function problems(): array
    {
        return [...$this->tableProblems(), ...$this->diskProblems()];
    }

    /**
     * The schema problems of the three integrity tables on the storage
     * connection, or none when the connection cannot be checked, which the
     * `schema` subject reports; a statement that fails is named by its class.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function tableProblems(): array
    {
        $connection = StorageConnection::resolvedName();

        if ((new EngineChecks($this->database))->blockingProblem($connection) !== null) {
            return [];
        }

        $schema = new SchemaChecks($this->database);

        // The framework declares nothing for a statement that fails, though it
        // throws a `QueryException`, whose message holds the statement
        try {
            return [
                ...$schema->problems($connection, IntegrityTables::checkpointsTable(), TableShape::checkpoints()),
                ...$schema->problems($connection, IntegrityTables::membersTable(), TableShape::members()),
                ...$schema->problems($connection, IntegrityTables::stateTable(), TableShape::state()),
            ];
        } catch (\PDOException $exception) { // @phpstan-ignore catch.neverThrown
            return [sprintf('The storage connection [%s] could not be read (%s).', $connection, get_debug_type($exception))];
        }
    }

    /**
     * The problem of a disk anchor's disk that is not configured in
     * `filesystems.disks`, looked up by the same dotted path the filesystem
     * manager resolves it by, or none; the null anchor names no disk.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function diskProblems(): array
    {
        $anchors = new AnchorSettings($this->config);

        if ($anchors->driver() !== AnchorDriver::DISK) {
            return [];
        }

        $disk = $anchors->disk();

        if (is_array($this->config->get("filesystems.disks.{$disk}"))) {
            return [];
        }

        return [sprintf('The disk [%s] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.', $disk)];
    }
}
