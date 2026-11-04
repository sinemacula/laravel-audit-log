<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * What a row of the lifecycle journal records. Each kind signs under a label of
 * its own, so a row signed as one kind never verifies as another.
 *
 * Only the kinds a lifecycle operation is asked for carry an authority: a hold,
 * a release, and an import's start and finish. A policy and a prune run, with
 * each of its chunks, are the package's own. The pruner replays the payloads of
 * policies, holds and releases alone: the policy versions already journalled,
 * and the holds still active, are all that a destructive decision reads of the
 * journal beyond its chain.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum JournalKind: string
{
    // A retention policy version, journalled by the first run under it
    case POLICY = 'policy';

    // A prune run's start or finish
    case PRUNE_RUN = 'prune_run';

    // One committed chunk of a prune run, with the prune record it signed
    case PRUNE = 'prune';

    // A hold placed on the entries its scope matches
    case HOLD = 'hold';

    // The release of an active hold
    case RELEASE = 'release';

    // An import's start, before its first entry
    case IMPORT_STARTED = 'import_started';

    // An import's end, or its close
    case IMPORT_FINISHED = 'import_finished';

    /**
     * The label a row of the kind is signed under, before the digest of its
     * signed fields.
     *
     * @return string
     */
    public function label(): string
    {
        return "audit-log:lifecycle:{$this->value}:v1\n";
    }

    /**
     * Whether a row of the kind names the authority that asked for it: a hold,
     * a release, and an import's start and finish do.
     *
     * @return bool
     */
    public function carriesAuthority(): bool
    {
        return match ($this) {
            self::HOLD,
            self::RELEASE,
            self::IMPORT_STARTED,
            self::IMPORT_FINISHED => true,
            default               => false,
        };
    }

    /**
     * Whether the pruner reads a row of the kind's payload when it replays the
     * journal: a policy's, since policy rows are one per version, and a hold's
     * and a release's, since they decide what a prune keeps.
     *
     * @return bool
     */
    public function readsPayloadToReplay(): bool
    {
        return match ($this) {
            self::POLICY,
            self::HOLD,
            self::RELEASE => true,
            default       => false,
        };
    }
}
