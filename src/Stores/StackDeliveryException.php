<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

/**
 * Thrown by a stack store once it has tried every destination and at least one
 * failed: it names each destination that failed and the class of what it failed
 * with, never the failure itself.
 *
 * The destinations that succeeded keep the record. Whether a failure was a
 * concurrency error, a lost connection or a statement refused by an aborted
 * PostgreSQL transaction is kept as a flag each, with the connection each
 * concurrency error or lost connection happened on, so a deadlock inside a host
 * transaction is still treated as fatal to that transaction, and a spill bound
 * to an aborted one is still discarded. It has no previous exception, so
 * neither a handler nor a log reaches a failure's message, SQL or bindings.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StackDeliveryException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $recordId
     * @param  non-empty-array<string, string>  $failures
     * @param  bool  $causedByConcurrency
     * @param  bool  $causedByLostConnection
     * @param  bool  $causedByAbortedHost
     * @param  list<?string>  $fatalConnections
     *
     * @internal
     */
    public function __construct(

        /** The id of the record not every destination received. */
        public readonly string $recordId,

        /** Each destination that failed, in order, with the class of what it failed with. */
        public readonly array $failures,

        /** Whether any destination failed with a concurrency error. */
        public readonly bool $causedByConcurrency,

        /** Whether any destination failed with a lost connection. */
        public readonly bool $causedByLostConnection,

        /** Whether any destination's statement was refused because a PostgreSQL transaction was already aborted. */
        public readonly bool $causedByAbortedHost,

        /** The connection each concurrency error or lost connection happened on, `null` for one that does not say. */
        public readonly array $fatalConnections,
    ) {
        $named = array_map(static fn (string $destination, string $class): string => sprintf('%s (%s)', $destination, $class), array_keys($failures), $failures);

        parent::__construct(sprintf('Audit record %s did not reach every destination: %s.', $recordId, implode(', ', $named)));
    }
}
