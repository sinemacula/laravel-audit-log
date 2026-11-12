<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * What one owner's key is made for: owner, tenant and category, so different
 * obligations never share a key and a tenant-local id never spans tenants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyUnit
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  string  $category
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The owner the key is made for. */
        #[\SensitiveParameter]
        public Reference $owner,

        /** The tenant of the records the key encrypts, or `null` for tenantless records. */
        #[\SensitiveParameter]
        public ?Reference $tenant,

        /** The category of the definitions whose fields the key encrypts. */
        public string $category,
    ) {
        if (preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
            throw new \InvalidArgumentException('A key unit\'s category must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.');
        }
    }

    /**
     * The unit's digest, as its key rows store it.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function digest(): string
    {
        return SubjectKeyRow::unitOf($this->owner->type, $this->owner->id, $this->tenant?->type, $this->tenant?->id, $this->category);
    }
}
