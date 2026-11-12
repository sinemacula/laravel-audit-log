<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\DetectsConcurrencyErrors;
use Illuminate\Database\DetectsLostConnections;
use Illuminate\Database\LostConnectionException;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * Tells failures that end a host transaction from those a savepoint recovers,
 * as Laravel recognises them, plus PostgreSQL's aborted transaction (`25P02`).
 *
 * Only the driver's root message is read, and never for SQLSTATE class 22 or
 * 23, whose message can quote a row's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailureClassifier
{
    use DetectsConcurrencyErrors, DetectsLostConnections;

    /** @var string The SQLSTATE of a PostgreSQL statement cancelled by its lock timeout. */
    private const string LOCK_TIMEOUT_STATE = '55P03';

    /** @var string The SQLSTATE of a statement run in a PostgreSQL transaction that is already aborted. */
    private const string ABORTED_HOST_STATE = '25P02';

    /** @var string The sanitised deadlock's message, which opens with the phrase Laravel recognises a deadlock by. */
    private const string DEADLOCK_MESSAGE = 'Deadlock found when trying to get lock; an audit write was abandoned inside the host transaction.';

    /** @var int The sanitised deadlock's code, the SQLSTATE of a serialisation failure. */
    private const int DEADLOCK_CODE = 40001;

    /** @var string What a SQLSTATE is: five digits or capital letters. */
    private const string SQL_STATE = '/\A[0-9A-Z]{5}\z/';

    /** @var list<string> The SQLSTATE classes of a data or constraint failure, whose driver message can quote a value of the row. */
    private const array VALUE_QUOTING_CLASSES = ['22', '23'];

    /**
     * A `DeadlockException` with no message of the original or previous
     * exception, which Laravel's `transaction()` still retries.
     *
     * @return \Illuminate\Database\DeadlockException
     */
    public static function sanitisedDeadlock(): DeadlockException
    {
        return new DeadlockException(self::DEADLOCK_MESSAGE, self::DEADLOCK_CODE);
    }

    /**
     * The failed statement without bindings or quoted values, so Laravel cannot
     * take a record's value for a deadlock and skip a savepoint rollback.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @return \Illuminate\Database\QueryException
     */
    public static function masked(#[\SensitiveParameter] QueryException $failure): QueryException
    {
        $class    = $failure instanceof UniqueConstraintViolationException ? UniqueConstraintViolationException::class : QueryException::class;
        $previous = $failure->getPrevious() ?? new \PDOException('The driver gave no exception.');

        return new $class($failure->getConnectionName(), $failure->getSql(), [], self::withoutQuotedValues($previous));
    }

    /**
     * Throw the failed statement as `masked()` gives it.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @return never
     *
     * @throws \Illuminate\Database\QueryException
     */
    public static function rethrowMasked(#[\SensitiveParameter] QueryException $failure): never
    {
        throw self::masked($failure);
    }

    /**
     * Whether Laravel recognises the failure as a concurrency error; its own
     * `DeadlockException` always is one.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    public function isConcurrencyError(#[\SensitiveParameter] \Throwable $failure): bool
    {
        if ($failure instanceof DeadlockException) {
            return true;
        }

        $root = self::rootOf($failure);

        return !self::quotesValues($root) && $this->causedByConcurrencyError($root);
    }

    /**
     * Whether PostgreSQL cancelled the statement on `lock_timeout` (`55P03`),
     * which Laravel does not count as a concurrency error.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    public function isLockTimeout(#[\SensitiveParameter] \Throwable $failure): bool
    {
        return self::stateOf(self::rootOf($failure)) === self::LOCK_TIMEOUT_STATE;
    }

    /**
     * Whether the failure is a database failure Laravel recognises as a lost
     * connection.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    public function isLostConnection(#[\SensitiveParameter] \Throwable $failure): bool
    {
        $root = self::rootOf($failure);

        if (!self::isDatabaseFailure($failure) && !self::isDatabaseFailure($root)) {
            return false;
        }

        return !self::quotesValues($root) && $this->causedByLostConnection($root);
    }

    /**
     * Whether the statement was refused because its PostgreSQL transaction was
     * already aborted (`25P02`).
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    public function isAbortedHost(#[\SensitiveParameter] \Throwable $failure): bool
    {
        if (!$failure instanceof \PDOException) {
            return false;
        }

        return ($failure->errorInfo[0] ?? null) === self::ABORTED_HOST_STATE || $failure->getCode() === self::ABORTED_HOST_STATE;
    }

    /**
     * The connection a query exception in the failure's chain names, if any.
     *
     * @param  \Throwable  $failure
     * @return ?string
     */
    public function connectionOf(#[\SensitiveParameter] \Throwable $failure): ?string
    {
        for ($current = $failure; $current !== null; $current = $current->getPrevious()) {
            if ($current instanceof QueryException) {
                // Laravel documents a string, but a thrower can give anything
                // @phpstan-ignore function.alreadyNarrowedType
                return is_string($current->connectionName) ? $current->connectionName : null;
            }
        }

        return null;
    }

    /**
     * Whether any failed connection had a transaction open; a failure that
     * names none counts as `$unnamedCounts` says.
     *
     * @param  array<int, ?string>  $failed
     * @param  list<string>  $open
     * @param  bool  $unnamedCounts
     * @return bool
     */
    public function reachesAnOpenTransaction(array $failed, array $open, bool $unnamedCounts): bool
    {
        foreach ($failed as $connection) {
            if ($connection === null ? $unnamedCounts : in_array($connection, $open, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The driver's exception at the root of the chain, whose message holds no
     * binding.
     *
     * @param  \Throwable  $failure
     * @return \Throwable
     */
    private static function rootOf(#[\SensitiveParameter] \Throwable $failure): \Throwable
    {
        $root = $failure;

        while (($previous = $root->getPrevious()) !== null) {
            $root = $previous;
        }

        return $root;
    }

    /**
     * Whether the failure comes from the database layer.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    private static function isDatabaseFailure(#[\SensitiveParameter] \Throwable $failure): bool
    {
        return $failure instanceof \PDOException || $failure instanceof LostConnectionException;
    }

    /**
     * Whether the failure is a data or constraint failure, whose driver message
     * can quote a row's value.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    private static function quotesValues(#[\SensitiveParameter] \Throwable $failure): bool
    {
        return in_array(substr(self::stateOf($failure) ?? '', 0, 2), self::VALUE_QUOTING_CLASSES, true);
    }

    /**
     * The driver's exception, its message replaced by the SQLSTATE when it can
     * quote a value.
     *
     * @param  \Throwable  $failure
     * @return \Throwable
     */
    private static function withoutQuotedValues(#[\SensitiveParameter] \Throwable $failure): \Throwable
    {
        if (!$failure instanceof \PDOException || !self::quotesValues($failure)) {
            return $failure;
        }

        $state             = self::stateOf($failure);
        $masked            = new \PDOException(sprintf('SQLSTATE[%s]: the driver\'s message is not kept, since it can quote a value.', $state));
        $masked->errorInfo = [$state, $failure->errorInfo[1] ?? null, null];

        return $masked;
    }

    /**
     * The failure's SQLSTATE, from its error information or else its code.
     *
     * @param  \Throwable  $failure
     * @return ?string
     */
    private static function stateOf(#[\SensitiveParameter] \Throwable $failure): ?string
    {
        $reported = $failure instanceof \PDOException ? ($failure->errorInfo[0] ?? null) : null;

        foreach ([$reported, $failure->getCode()] as $candidate) {
            if (is_string($candidate) && preg_match(self::SQL_STATE, $candidate) === 1) {
                return $candidate;
            }
        }

        return null;
    }
}
