<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery\Enums;

use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;

/**
 * What a failed write of one record does, from its timing, whether it fails
 * closed and the configured failure mode.
 *
 * A transactional record is never spilled: a replay must never turn uncommitted
 * work into committed evidence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum FailureRule: string
{
    // Spill, report and dispatch `AuditWriteFailed`, then let the recording
    // code go on
    case REPORT = 'report';

    // Spill and dispatch `AuditWriteFailed`, then throw it to the recording
    // code
    case SPILL_AND_THROW = 'spill_and_throw';

    // Dispatch `AuditWriteFailed` and throw it, never leaving a replayable
    // spill
    case THROW = 'throw';

    /**
     * The rule for a record; a transactional one always throws unspilled.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode  $mode
     * @return self
     */
    public static function for(Timing $timing, bool $failClosed, FailureMode $mode): self
    {
        if ($timing === Timing::TRANSACTIONAL) {
            return self::THROW;
        }

        return $failClosed || $mode === FailureMode::THROW ? self::SPILL_AND_THROW : self::REPORT;
    }
}
