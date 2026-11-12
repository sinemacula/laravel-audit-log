<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;

/**
 * Reported when a lifecycle operation committed but its record was not written;
 * the journal stands and `audit-log:reconcile` repairs it.
 *
 * It never wraps the failure, so nothing a record or a failed statement held
 * reaches its reader.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LifecycleRecordFailedException extends \RuntimeException
{
    /** @var string The message, by the operation, the code and why the record could not be written. */
    private const string MESSAGE = 'The lifecycle operation `%s` committed, and its `%s` record could not be written (%s); run `audit-log:reconcile`.';

    /**
     * Constructor.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  string  $failure
     */
    private function __construct(

        /** The id of the operation that committed. */
        public readonly string $operationId,

        /** The code of the record that could not be written. */
        public readonly PackageActivity $activity,

        /** Why: the class of the failure, or what refused the write. */
        public readonly string $failure,
    ) {
        parent::__construct(sprintf(self::MESSAGE, $operationId, $activity->value, $failure));
    }

    /**
     * The exception for a record whose write failed or was refused.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  string  $failureClass
     * @return self
     */
    public static function of(string $operationId, PackageActivity $activity, string $failureClass): self
    {
        return new self($operationId, $activity, $failureClass);
    }

    /**
     * The exception for a write neither the store nor the outbox acknowledged.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @return self
     */
    public static function unacknowledged(string $operationId, PackageActivity $activity): self
    {
        return new self($operationId, $activity, 'it was never acknowledged');
    }

    /**
     * The exception for a record not attempted because a transaction was open
     * on the acknowledging connection.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  string  $connection
     * @return self
     */
    public static function inTransaction(string $operationId, PackageActivity $activity, string $connection): self
    {
        return new self($operationId, $activity, sprintf('a transaction is open on the `%s` connection', $connection));
    }
}
