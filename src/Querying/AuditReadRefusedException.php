<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;

/**
 * Thrown when a read is refused or cannot be recorded, so nothing it found is
 * disclosed; `$reason` tells the causes apart without reading the message.
 *
 * Its message names classes and connections only and it carries no previous
 * exception, so nothing that was read can reach a reporter.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuditReadRefusedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal  $reason
     * @param  ?string  $class
     * @param  ?string  $connection
     */
    private function __construct(

        // Passed to the parent constructor, which owns the message
        string $message,

        /** Why the read was refused. */
        public readonly ReadRefusal $reason,

        /** The store class or the failing exception class, or `null`. */
        public readonly ?string $class = null,

        /** The connection a transaction was open on, or `null`. */
        public readonly ?string $connection = null,
    ) {
        parent::__construct($message);
    }

    /**
     * The refusal of a read entered while another read, a write or an event
     * mapper was running.
     *
     * @return self
     */
    public static function reentrant(): self
    {
        $message = 'The audit trail was read while a read of it, an audit record\'s write or its failure, or an event mapper was running,'
            . ' so the read was refused.';

        return new self($message, ReadRefusal::REENTRANT);
    }

    /**
     * The refusal of a read while a transaction is open on the connection.
     *
     * @param  string  $connection
     * @return self
     */
    public static function inTransaction(string $connection): self
    {
        $message = 'The audit trail is not read while a transaction is open on the [%s] connection,'
            . ' since the read\'s record, or a row it would show, could still be rolled back.';

        return new self(sprintf($message, $connection), ReadRefusal::IN_TRANSACTION, connection: $connection);
    }

    /**
     * The refusal of a read through a store that does not say it is durable.
     *
     * @param  string  $storeClass
     * @return self
     */
    public static function notDurable(string $storeClass): self
    {
        $message = 'The audit trail is read only through a durable store, and %s does not say it is. Bind one, or use the outbox.';

        return new self(sprintf($message, $storeClass), ReadRefusal::NOT_DURABLE, $storeClass);
    }

    /**
     * The refusal of a read through a store that keeps no attachments.
     *
     * @param  string  $storeClass
     * @return self
     */
    public static function keepsNoArtifacts(string $storeClass): self
    {
        $message = 'The audit trail is read only through a store that keeps attachments, and %s keeps none.'
            . ' Bind one that does, such as the database store.';

        return new self(sprintf($message, $storeClass), ReadRefusal::KEEPS_NO_ARTIFACTS, $storeClass);
    }

    /**
     * The refusal of a read whose record was not written or acknowledged.
     *
     * @return self
     */
    public static function unrecorded(): self
    {
        return new self('The read of the audit trail could not be recorded, so nothing was disclosed.', ReadRefusal::UNRECORDED);
    }

    /**
     * The refusal of a read whose record would not keep its evidence exactly.
     *
     * @return self
     */
    public static function evidenceAltered(): self
    {
        return new self('The record of the read of the audit trail would not keep its evidence exactly, so the read was refused.', ReadRefusal::EVIDENCE_ALTERED);
    }

    /**
     * The refusal of a read that failed with an exception of the class.
     *
     * @param  string  $exceptionClass
     * @return self
     */
    public static function failed(string $exceptionClass): self
    {
        return new self(sprintf('The read of the audit trail failed with %s, so nothing was disclosed.', $exceptionClass), ReadRefusal::FAILED, $exceptionClass);
    }

    /**
     * The refusal of a recorded export whose file could not be published.
     *
     * @param  string  $exceptionClass
     * @return self
     */
    public static function publishFailed(string $exceptionClass): self
    {
        $message = 'The export was recorded, but its file could not be published (%s), so nothing was published.';

        return new self(sprintf($message, $exceptionClass), ReadRefusal::PUBLISH_FAILED, $exceptionClass);
    }
}
