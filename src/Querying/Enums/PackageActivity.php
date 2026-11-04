<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * The codes the package records of its own read path: each read, count and
 * export of the trail, each verification of an export, and an export that could
 * not be published. Each is under the reserved `audit_log.` prefix, and this
 * enum is the only way to mint a code under it.
 *
 * Every definition is version 1, in the `audit` category, and drops every field
 * it does not list; it keeps exactly the evidence its record carries. The event
 * catalogue holds these definitions from the moment it is made, so no
 * application registers them and none can define them differently.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum PackageActivity: string implements DefinesAuditEvents
{
    // A page of the trail was read
    case TRAIL_READ = 'audit_log.trail_read';

    // The entries of the trail were counted
    case TRAIL_COUNTED = 'audit_log.trail_counted';

    // The trail was exported to a file
    case TRAIL_EXPORTED = 'audit_log.trail_exported';

    // An export was verified against the trail
    case EXPORT_VERIFIED = 'audit_log.export_verified';

    // An export was journalled and its file could not be published
    case EXPORT_PUBLISH_FAILED = 'audit_log.export_publish_failed';

    /** @var string The category every package code is stored under. */
    private const string CATEGORY = 'audit';

    /**
     * The definition of this case's event code: version 1, the `audit`
     * category, every field it does not list dropped, and the evidence of the
     * read, the count, the export, the verification or the failed publication
     * retained.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::permissive(EventCode::package($this))
            ->unlisted(FieldHandling::DROP)
            ->category(self::CATEGORY)
            ->retain(...$this->retained());
    }

    /**
     * Whether the activity reads the trail, an export's verification included;
     * a failed publication is not a read.
     *
     * @return bool
     */
    public function isRead(): bool
    {
        return match ($this) {
            self::EXPORT_PUBLISH_FAILED => false,
            default                     => true,
        };
    }

    /**
     * The properties this case's record keeps, in the order it gives them.
     *
     * @return non-empty-list<string>
     */
    private function retained(): array
    {
        return match ($this) {
            self::TRAIL_READ            => ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'outcome'],
            self::TRAIL_COUNTED         => ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'returned', 'outcome'],
            self::TRAIL_EXPORTED        => ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'format', 'returned', 'file_sha256', 'outcome'],
            self::EXPORT_VERIFIED       => ['purpose', 'scope_fingerprint', 'fingerprint_key', 'policy', 'export_entry', 'verdict', 'findings', 'outcome'],
            self::EXPORT_PUBLISH_FAILED => ['export_entry', 'outcome'],
        };
    }
}
