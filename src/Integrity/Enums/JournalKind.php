<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * What a row of the lifecycle journal records. Each kind signs under a label of
 * its own, so a row signed as one kind never verifies as another.
 *
 * Only the kinds a lifecycle operation is asked for carry an authority: a hold,
 * a release, an import's start and finish, an erasure, a reinstatement, a
 * rewrap batch and a reconciled restore. A policy and a prune run, with each of
 * its chunks, are the package's own. The pruner replays the payloads of
 * policies, holds and releases alone: the policy versions already journalled,
 * and the holds still active, are all that a destructive decision reads of the
 * journal beyond its chain. The privacy kinds are read where the owners' keys
 * are checked, never by the pruner's replay.
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

    // An owner's erasure: the keys it destroyed, the keys it kept and why, and
    // the generation floor it set
    case ERASURE = 'erasure';

    // An erased owner's reinstatement, so new keys may be created above the
    // floor its erasure set
    case REINSTATE = 'reinstate';

    // One committed batch of a rewrap: each key's wrapping before and after
    case REWRAP = 'rewrap';

    // A restored database reconciled, once every owner its erasures file names
    // is erased again, with the head the anchor held
    case RESTORE_RECONCILED = 'restore_reconciled';

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
     * a release, an import's start and finish, an erasure, a reinstatement, a
     * rewrap batch and a reconciled restore do.
     *
     * @return bool
     */
    public function carriesAuthority(): bool
    {
        return match ($this) {
            self::HOLD,
            self::RELEASE,
            self::IMPORT_STARTED,
            self::IMPORT_FINISHED,
            self::ERASURE,
            self::REINSTATE,
            self::REWRAP,
            self::RESTORE_RECONCILED => true,
            default                  => false,
        };
    }

    /**
     * Whether the pruner reads a row of the kind's payload when it replays the
     * journal: a policy's, since policy rows are one per version, and a hold's
     * and a release's, since they decide what a prune keeps. No privacy kind's
     * is: an erasure, a reinstatement, a rewrap and a reconciled restore decide
     * nothing a prune keeps.
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
