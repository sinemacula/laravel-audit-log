<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;

/**
 * Reported when a lifecycle operation committed and the record of its activity
 * could not be written after it: the write failed, was refused, was never
 * acknowledged, or was not attempted because a transaction was open on the
 * connection that would acknowledge it. The operation stands, since its journal
 * row committed with it and the journal is the authority, and
 * `audit-log:reconcile` records what is missing.
 *
 * It names the operation's id, the record's code and the class of the failure,
 * or the open connection, and nothing else: the package never gives it another
 * exception, so nothing a record or a failed statement held reaches whoever
 * reads it.
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
     * The exception for a record whose write failed or was refused, by the
     * class of the failure.
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
     * The exception for a record whose write returned without the store or the
     * outbox acknowledging it, so it is never taken as written.
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
     * on the connection that would acknowledge it, by that connection's name.
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
