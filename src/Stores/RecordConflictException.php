<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

/**
 * Thrown when a record's id is held by an entry that is not the same record, or
 * the record was pruned; what is stored is never overwritten.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecordConflictException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $id
     */
    public function __construct(

        // Handed to the parent, not kept as a property
        string $message,

        /** The id the record and the existing entry share, or the pruned record's. */
        public readonly string $id,
    ) {
        parent::__construct($message);
    }

    /**
     * The exception for an existing entry whose captured content differs from
     * the record's.
     *
     * @param  string  $id
     * @return self
     */
    public static function differentContent(string $id): self
    {
        return new self(sprintf('An audit entry with id %s already exists with different captured content.', $id), $id);
    }

    /**
     * The exception for a bulk record stored with another artifact, without its
     * own, or as an artifact without its entry.
     *
     * @param  string  $id
     * @return self
     */
    public static function differentArtifact(string $id): self
    {
        return new self(sprintf('The record %s is stored with another artifact, or without its own.', $id), $id);
    }

    /**
     * The exception for a record retention has already pruned.
     *
     * @param  string  $id
     * @return self
     */
    public static function alreadyPruned(string $id): self
    {
        return new self(sprintf('The record `%s` was pruned; it is not stored again.', $id), $id);
    }

    /**
     * The exception for an existing entry whose stored row fails verification.
     *
     * @param  string  $id
     * @return self
     */
    public static function unverified(string $id): self
    {
        return new self(sprintf('An audit entry with id %s already exists, and its stored row fails verification.', $id), $id);
    }
}
