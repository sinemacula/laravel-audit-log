<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\Contribution;

/**
 * Context contributor contract: one ordered step that fills the gaps in a
 * captured record, after the package's own.
 *
 * The first to fill a field wins and an explicit value is never replaced. An
 * implementation keeps no state and never calls a guard's `user()`, which loads
 * a user and dispatches `Authenticated`; its queries fall outside the package's
 * budgets.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ContextContributor
{
    /**
     * Fill what this contributor knows into the record being captured.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     */
    public function contribute(Contribution $contribution): void;
}
