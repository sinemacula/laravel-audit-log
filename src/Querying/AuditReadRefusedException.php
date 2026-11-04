<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;

/**
 * Thrown when a read of the trail, a count, an export or the verification of an
 * export is refused or cannot be recorded, so nothing it would have disclosed
 * leaves the package: it was entered while another read, an audit record's
 * write or its failure, or an event mapper was running; a transaction that
 * could still roll its record back was open; the store could not keep its
 * record; its record could not be written or would not have kept its evidence
 * exactly; or the read itself failed, or its export could not be published.
 *
 * Its cause is `$reason`, a `ReadRefusal`, and the class it names, a store's or
 * an exception's, is `$class`, and the connection it names is `$connection`, so
 * a caller tells the causes apart without reading the message. Its message
 * names classes and connections alone, never a value, a statement or a binding,
 * and it never carries another exception, so nothing of what was read, or of
 * what failed, can reach a reporter through it.
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

        // The message, built by the named constructor from the class or the
        // connection alone
        string $message,

        /** Why the read was refused. */
        public readonly ReadRefusal $reason,

        /** The class of the store that cannot keep the record, or of the exception the read or the publication failed with, or `null`. */
        public readonly ?string $class = null,

        /** The connection a transaction was open on, or `null`. */
        public readonly ?string $connection = null,
    ) {
        parent::__construct($message);
    }

    /**
     * The refusal of a read entered while a read of the trail, an audit
     * record's write or the handling of its failure, or an event mapper was
     * running.
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
     * The refusal of a read while a transaction that could still roll its
     * record back, or show a row its caller could still roll back, is open on
     * the connection.
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
     * The refusal of a read whose record the store, of the class, does not say
     * it keeps durably.
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
     * The refusal of a read whose record's attachment the store, of the class,
     * does not keep.
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
     * The refusal of a read whose record could not be written, or was never
     * acknowledged.
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
     * The refusal of an export that was recorded and whose file could not be
     * published, with an exception of the class.
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
