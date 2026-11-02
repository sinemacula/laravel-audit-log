<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * An application's contributor filling the actor and the guard, as one for a
 * guard the package cannot read would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActorFillingContributor implements ContextContributor
{
    /** @var string The type of the actor it fills. */
    public const string TYPE = 'service_account';

    /** @var string The id of the actor it fills. */
    public const string ID = 'service-account-1';

    /** @var string The guard it fills. */
    public const string GUARD = 'service';

    /**
     * Fill the actor and the guard.
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
        $contribution->fillActor(Reference::of(self::TYPE, self::ID));
        $contribution->fillGuard(self::GUARD);
    }
}
