<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

/**
 * Thrown by a stack store when any destination failed, naming each with its
 * failure's class; it has no previous exception, so no record value leaks.
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

        /** Each failed destination, in order, with its failure's class. */
        public readonly array $failures,

        /** Whether any destination failed with a concurrency error. */
        public readonly bool $causedByConcurrency,

        /** Whether any destination failed with a lost connection. */
        public readonly bool $causedByLostConnection,

        /** Whether any destination's statement hit an aborted PostgreSQL transaction. */
        public readonly bool $causedByAbortedHost,

        /** The connection of each concurrency error or lost connection, `null` when unnamed. */
        public readonly array $fatalConnections,
    ) {
        $named = array_map(static fn (string $destination, string $class): string => sprintf('%s (%s)', $destination, $class), array_keys($failures), $failures);

        parent::__construct(sprintf('Audit record %s did not reach every destination: %s.', $recordId, implode(', ', $named)));
    }
}
