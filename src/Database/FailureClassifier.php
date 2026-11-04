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
 * Tells the database failures that end a host's transaction from those a
 * savepoint recovers: a concurrency error (a deadlock, a serialisation failure,
 * a lock wait timeout or a locked database) and a lost connection, each as
 * Laravel itself recognises them, so the package and the framework agree, and a
 * PostgreSQL transaction that was already aborted before the write (SQLSTATE
 * `25P02`).
 *
 * Laravel recognises some of these by the exception's message, so it is read to
 * classify the failure and nothing of it is kept. A `QueryException`'s message
 * holds the statement with its bindings, so the message read is that of the
 * driver's own exception at the root of the chain, and a data or constraint
 * failure (SQLSTATE class `22` or `23`), whose driver message can quote a
 * value, is neither: a record's value can never make an ordinary failure look
 * fatal. A `DeadlockException` is always a concurrency error, because Laravel
 * throws it having left the savepoint it came from without a rollback. A lost
 * connection is only ever a database failure, so a phrase in anything else's
 * message does not count.
 *
 * A failure ends only the transaction on the connection it happened on, so
 * `connectionOf()` names that connection when the failure says, for the caller
 * to compare with the transactions that were open.
 *
 * Inside a host transaction a concurrency error is replaced by
 * `sanitisedDeadlock()`: an exception without the original's message or
 * previous exception, which Laravel still recognises, so the host's
 * `transaction()` retries it as it would the original. Inside a savepoint a
 * failed statement is replaced by `masked()` before Laravel sees it, for the
 * same reason.
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
     * The exception a concurrency error inside a host transaction is replaced
     * by: a `DeadlockException` with a fixed message and the code `40001`, and
     * no previous exception, which Laravel recognises as a concurrency error.
     *
     * @return \Illuminate\Database\DeadlockException
     */
    public static function sanitisedDeadlock(): DeadlockException
    {
        return new DeadlockException(self::DEADLOCK_MESSAGE, self::DEADLOCK_CODE);
    }

    /**
     * The failed statement as Laravel may safely read it: the same class on the
     * same connection, with no binding in its message and no value a driver's
     * message quoted, so Laravel cannot take a record's value for a concurrency
     * error and leave a savepoint without its rollback. The SQLSTATE and driver
     * code are kept.
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
     * Throw the failed statement masked, as `masked()` gives it, so a caller
     * that catches one rethrows it with no binding and no quoted value.
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
     * Whether the failure is a concurrency error, as Laravel recognises one: a
     * deadlock, a serialisation failure, a lock wait timeout or a locked
     * database. Laravel's own `DeadlockException` always is, whatever its code
     * and message became on the way.
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
     * Whether the failure is a statement PostgreSQL cancelled because it waited
     * longer than `lock_timeout` for a lock (SQLSTATE `55P03`), read at the
     * root of the chain. Laravel recognises MySQL's lock wait timeout as a
     * concurrency error but not this one, which a caller that retries a whole
     * transaction can treat the same way.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    public function isLockTimeout(#[\SensitiveParameter] \Throwable $failure): bool
    {
        return self::stateOf(self::rootOf($failure)) === self::LOCK_TIMEOUT_STATE;
    }

    /**
     * Whether the failure is a lost connection, as Laravel recognises one, and
     * a database failure at all: a phrase in another exception's message says
     * nothing of a database connection.
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
     * Whether the failure is a statement refused because the PostgreSQL
     * transaction it ran in was already aborted (SQLSTATE `25P02`), read from
     * the driver's error information or the failure's code.
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
     * The connection the failure happened on, when a query exception in its
     * chain says, and `null` when none does.
     *
     * @param  \Throwable  $failure
     * @return ?string
     */
    public function connectionOf(#[\SensitiveParameter] \Throwable $failure): ?string
    {
        for ($current = $failure; $current !== null; $current = $current->getPrevious()) {
            if ($current instanceof QueryException) {
                // Laravel documents a string, but the alias is whatever the
                // code that threw the query exception gave it.
                // @phpstan-ignore function.alreadyNarrowedType
                return is_string($current->connectionName) ? $current->connectionName : null;
            }
        }

        return null;
    }

    /**
     * Whether any of the connections failures happened on had a transaction
     * open: a connection named is looked up among those open, and a failure
     * that names none counts as the caller says.
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
     * The driver's own exception at the root of the failure's chain, whose
     * message holds no binding, or the failure itself when it has none.
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
     * can quote a value of the row, so its message decides nothing.
     *
     * @param  \Throwable  $failure
     * @return bool
     */
    private static function quotesValues(#[\SensitiveParameter] \Throwable $failure): bool
    {
        return in_array(substr(self::stateOf($failure) ?? '', 0, 2), self::VALUE_QUOTING_CLASSES, true);
    }

    /**
     * The driver's exception with the message of a data or constraint failure
     * replaced by its SQLSTATE, and any other as it is.
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
     * The failure's SQLSTATE: the first element of its error information, or
     * else its code, whichever is a SQLSTATE first.
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
