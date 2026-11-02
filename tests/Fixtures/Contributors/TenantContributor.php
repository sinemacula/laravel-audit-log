<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * An application's contributor filling the tenant every record happens in, as a
 * multi-tenant application would from its own state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantContributor implements ContextContributor
{
    /** @var string The type of the tenant it fills. */
    public const string TYPE = 'organisation';

    /** @var string The id of the tenant it fills. */
    public const string ID = 'organisation-1';

    /**
     * Fill the tenant.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function contribute(Contribution $contribution): void
    {
        $contribution->fillTenant(Reference::of(self::TYPE, self::ID));
    }
}
