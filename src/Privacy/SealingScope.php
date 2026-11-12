<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * What every value of one record is sealed for, giving each value its field
 * context; a record with no owner needs no log id and gives no context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealingScope
{
    /** @var string The column of an address, a path on its own. */
    private const string ADDRESS = 'ip';

    /** @var list<\SineMacula\Laravel\AuditLog\Records\Reference> Every owner the record encrypts for, each once, sorted by type and then id. */
    private array $owners;

    /**
     * Constructor.
     *
     * @param  string  $entryId
     * @param  ?string  $logId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  string  $category
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function __construct(

        /** The id of the entry the record will be stored as, a lower-case UUID. */
        private string $entryId,

        /** The id of the log the entry is signed into, or `null` for a record with no owner, which seals nothing. */
        private ?string $logId,

        /** The record's tenant, or `null` for a tenantless record. */
        private ?Reference $tenant,

        /** The category of the record's definition. */
        private string $category,

        // In any order and repeated freely; deduplicated into `$this->owners`
        #[\SensitiveParameter]
        array $owners,
    ) {
        if ($logId === null && $owners !== []) {
            self::refuse('A record with an owner is sealed for the log its entry is signed into.');
        }

        // A context at the address checks the other parts and sorts the owners
        $this->owners = $logId === null ? [] : (new FieldContext($entryId, [self::ADDRESS], $logId, $tenant, $category, $owners))->owners;
    }

    /**
     * The context of the value at the path.
     *
     * @param  array<array-key, int|string>  $path
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldContext
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function at(#[\SensitiveParameter] array $path): FieldContext
    {
        if ($this->logId === null) {
            self::refuse('A record with no owner seals nothing, so its scope gives no context.');
        }

        return new FieldContext($this->entryId, $path, $this->logId, $this->tenant, $this->category, $this->owners);
    }

    /**
     * Refuse a use of the scope a record with no owner never needs.
     *
     * @param  string  $message
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuse(string $message): never
    {
        throw new \LogicException($message);
    }
}
