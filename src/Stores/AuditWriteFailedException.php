<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

/**
 * Thrown, or reported, when a record could not be written, in place of the
 * exception the write failed with, which can hold the record's values in its
 * message, its SQL and its bindings.
 *
 * It holds only what may be said about the failure without saying anything of
 * the record: the record's id and code, the operation that failed, the store,
 * the exception's class, and, for a database failure, its SQLSTATE, its numeric
 * driver code and the connection's alias. Its message is built from those
 * alone, and it has no previous exception, so neither a handler nor a log
 * reaches the original.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuditWriteFailedException extends \RuntimeException
{
    /** @var ?string The id of the record that was not written, or `null` when a drain stopped before any one record was read. */
    public readonly ?string $recordId;

    /** @var ?string The record's event code, or `null` when it could not be read. */
    public readonly ?string $eventCode;

    /** @var string The step of the write path that failed, a `FailedOperation` value. */
    public readonly string $operation;

    /** @var string The class of the store the write failed on. */
    public readonly string $store;

    /** @var string The class of the exception the write failed with. */
    public readonly string $exceptionClass;

    /** @var ?string The failure's SQLSTATE, or `null` when it is not a database failure or gave none. */
    public readonly ?string $sqlState;

    /** @var ?int The driver's numeric error code, or `null` when it gave none. */
    public readonly ?int $driverCode;

    /** @var ?string The alias of the connection the write failed on, never its host or port. */
    public readonly ?string $connection;

    /** @var ?string The id of the destination that failed, for a delivery to one of several; several ids separated by commas when a stack's destinations failed together. */
    public readonly ?string $destination;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     *
     * @internal
     */
    public function __construct(WriteDiagnostics $diagnostics)
    {
        $this->recordId       = $diagnostics->recordId;
        $this->eventCode      = $diagnostics->eventCode;
        $this->operation      = $diagnostics->operation->value;
        $this->store          = $diagnostics->store;
        $this->exceptionClass = $diagnostics->exceptionClass;
        $this->sqlState       = $diagnostics->sqlState;
        $this->driverCode     = $diagnostics->driverCode;
        $this->connection     = $diagnostics->connection;
        $this->destination    = $diagnostics->destination;

        parent::__construct(self::messageOf($diagnostics));
    }

    /**
     * The message, built from the diagnostics alone, naming each optional field
     * only when it is known.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     * @return string
     */
    private static function messageOf(WriteDiagnostics $diagnostics): string
    {
        $details = array_filter([
            'SQLSTATE'    => $diagnostics->sqlState,
            'driver code' => $diagnostics->driverCode,
            'connection'  => $diagnostics->connection,
            'destination' => $diagnostics->destination,
        ], static fn (int|string|null $detail): bool => $detail !== null);

        $message = sprintf(
            '%s: %s failed on %s with %s',
            self::subjectOf($diagnostics),
            $diagnostics->operation->value,
            $diagnostics->store,
            $diagnostics->exceptionClass,
        );

        foreach ($details as $name => $detail) {
            $message .= sprintf(', %s %s', $name, $detail);
        }

        return $message . '.';
    }

    /**
     * What the message is about: the record that was not written, or, for a
     * drain stopped before it read any one record, none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     * @return string
     */
    private static function subjectOf(WriteDiagnostics $diagnostics): string
    {
        if ($diagnostics->recordId === null) {
            return 'No audit record was read';
        }

        $code = $diagnostics->eventCode === null ? '' : sprintf(' (%s)', $diagnostics->eventCode);

        return sprintf('Audit record %s%s was not written', $diagnostics->recordId, $code);
    }
}
