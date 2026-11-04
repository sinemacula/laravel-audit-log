<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * The codes the package records of its own activity: the read path's reads,
 * counts, exports and their verification, the lifecycle's prunes, holds,
 * releases and imports, and its owners' erasures and the reinstatements and
 * rewraps of their keys. Each is under the reserved `audit_log.` prefix, and
 * this enum is the only way to mint a code under it. It stays among the read
 * path's enums, which the records already name, so no layer gains a dependency
 * to name it.
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

    // A retention run pruned the entries its policy no longer keeps
    case PRUNED = 'audit_log.pruned';

    // A hold was placed, keeping the entries it covers from retention
    case HELD = 'audit_log.held';

    // A hold was released, returning its entries to retention
    case RELEASED = 'audit_log.released';

    // Records from another source were imported into the trail
    case IMPORTED = 'audit_log.imported';

    // An owner's keys were erased, so the fields sealed under them never read
    case SUBJECT_ERASED = 'audit_log.subject_erased';

    // The owners' keys were wrapped again under the current wrapping key
    case KEYS_REWRAPPED = 'audit_log.keys_rewrapped';

    // An erased owner was reinstated, so new keys may be made for them
    case KEYS_REINSTATED = 'audit_log.keys_reinstated';

    /** @var string The category every package code is stored under. */
    private const string CATEGORY = 'audit';

    /**
     * The definition of this case's event code: version 1, the `audit`
     * category, every field it does not list dropped, and the evidence of the
     * read, the count, the export, the verification, the failed publication,
     * the prune, the hold, the release, the import, the erasure, the rewrap or
     * the reinstatement retained.
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
     * a failed publication is not a read, and nor is any of the lifecycle's
     * activity or of its owners' keys.
     *
     * @return bool
     */
    public function isRead(): bool
    {
        return match ($this) {
            self::EXPORT_PUBLISH_FAILED,
            self::PRUNED,
            self::HELD,
            self::RELEASED,
            self::IMPORTED,
            self::SUBJECT_ERASED,
            self::KEYS_REWRAPPED,
            self::KEYS_REINSTATED => false,
            default               => true,
        };
    }

    /**
     * Whether retention never prunes the code's entries: an export's journal is
     * its evidence for as long as the database lives.
     *
     * @return bool
     */
    public function isProtected(): bool
    {
        return match ($this) {
            self::TRAIL_EXPORTED => true,
            default              => false,
        };
    }

    /**
     * The properties this case's record keeps, in the order it gives them.
     *
     * @return non-empty-list<string>
     *
     * @throws \LogicException
     */
    private function retained(): array
    {
        return match ($this) {
            self::TRAIL_READ => [
                'purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'reveal',
                'fields', 'outcome',
            ],
            self::TRAIL_COUNTED         => ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'returned', 'outcome'],
            self::TRAIL_EXPORTED        => ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'format', 'returned', 'file_sha256', 'outcome'],
            self::EXPORT_VERIFIED       => ['purpose', 'scope_fingerprint', 'fingerprint_key', 'policy', 'export_entry', 'verdict', 'findings', 'outcome'],
            self::EXPORT_PUBLISH_FAILED => ['export_entry', 'outcome'],
            default                     => $this->operationRetained(),
        };
    }

    /**
     * The properties the record of an operation on the trail or on its owners'
     * keys keeps, in the order it gives them; a read path's code has none here.
     *
     * @return non-empty-list<string>
     *
     * @throws \LogicException
     */
    private function operationRetained(): array
    {
        return match ($this) {
            self::PRUNED => [
                'operation_id', 'status', 'policy_version', 'deleted', 'seals', 'held', 'pending_delivery', 'skipped_seals',
                'categories', 'tenants_affected', 'outcome',
            ],
            self::HELD     => ['operation_id', 'hold_id', 'basis', 'scope_digest', 'review_by', 'authority_reason', 'outcome'],
            self::RELEASED => ['operation_id', 'hold_id', 'authority_reason', 'outcome'],
            self::IMPORTED => [
                'operation_id', 'batch_id', 'source_id', 'format', 'status', 'lines_read', 'imported', 'duplicates', 'conflicts',
                'rejected', 'hold_id', 'authority_reason', 'outcome',
            ],
            self::SUBJECT_ERASED => [
                'operation_id', 'erasure_id', 'owner_fingerprint', 'fingerprint_key', 'status', 'keys_destroyed', 'keys_kept',
                'entries_affected', 'blocked', 'pending_accepted', 'authority_reason', 'outcome',
            ],
            self::KEYS_REWRAPPED => [
                'operation_id', 'status', 'keys_rewrapped', 'keys_rotated', 'keys_skipped', 'wrap_key_id', 'batches', 'authority_reason',
                'outcome',
            ],
            self::KEYS_REINSTATED => ['operation_id', 'reinstatement_id', 'owner_fingerprint', 'fingerprint_key', 'generation_floor', 'authority_reason', 'outcome'],
            default               => throw new \LogicException(sprintf('`%s` is not the code of an operation.', $this->value)),
        };
    }
}
