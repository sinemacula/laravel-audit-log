<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

/**
 * Thrown when a record is stored under an id an entry already holds, and the
 * entry is not the same record: its captured content differs, or its stored row
 * fails verification. A bulk record conflicts too when its entry is stored with
 * another artifact or without its own, or its artifact without its entry. What
 * is stored is kept as it is; the record is never written over it.
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

        // What is wrong.
        string $message,

        /** The id the record and the existing entry share. */
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
     * The exception for a bulk record whose entry is stored with another
     * artifact, or without its own, or whose artifact is stored without its
     * entry.
     *
     * @param  string  $id
     * @return self
     */
    public static function differentArtifact(string $id): self
    {
        return new self(sprintf('The record %s is stored with another artifact, or without its own.', $id), $id);
    }

    /**
     * The exception for an existing entry whose stored row fails verification,
     * so it cannot be the record.
     *
     * @param  string  $id
     * @return self
     */
    public static function unverified(string $id): self
    {
        return new self(sprintf('An audit entry with id %s already exists, and its stored row fails verification.', $id), $id);
    }
}
