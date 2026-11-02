<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\Contribution;

/**
 * Context contributor contract: one step of the ordered seam that fills the
 * gaps in a record as it is captured. The package's defaults come first (the
 * origin, then the request, then the actor), and `AuditLog::contribute()`
 * extends the seam with the application's own, in the order they are
 * registered.
 *
 * A contributor only fills gaps: it never replaces an explicit value, and the
 * first to fill a field wins, so a default that fills a field leaves nothing
 * for a later contributor. It is resolved from the current container for every
 * capture and must keep no state between calls. It must never call a guard's
 * `user()`, which loads a user and dispatches `Authenticated`. It may query at
 * its own cost: the package's query budgets cover the defaults only.
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
