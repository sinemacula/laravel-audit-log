<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery\Enums;

use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;

/**
 * What a failed write of one record does, decided once from its timing, whether
 * it was asked to fail closed and the configured failure mode: spill, report
 * and dispatch `AuditWriteFailed` and let the code go on, or spill, dispatch it
 * and throw, or dispatch it and throw without leaving a replayable spill.
 *
 * A transactional record is never spilled, whatever else is set: it describes
 * work that has not committed, and a replay must never turn it into committed
 * evidence. A record asked to fail closed, or any record under the `throw`
 * mode, is spilled and thrown. Every other record is spilled and reported.
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
     * The rule for a record of the timing, asked to fail closed or not, under
     * the failure mode: `THROW` for a transactional record whatever else is
     * set, then `SPILL_AND_THROW` for a record asked to fail closed or under
     * the `throw` mode, and `REPORT` otherwise.
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
