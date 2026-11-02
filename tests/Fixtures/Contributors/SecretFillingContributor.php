<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * An application's contributor filling a secret into the context and an actor,
 * after the recorder's first snapshot, so a test can see that minimising reads
 * what the contributors filled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SecretFillingContributor implements ContextContributor
{
    /** @var string The secret it fills into the context. */
    public const string SECRET = 's3cr3t';

    /** @var string The type of the actor it fills. */
    public const string ACTOR_TYPE = 'service_account';

    /** @var string The id of the actor it fills. */
    public const string ACTOR_ID = 'service-account-1';

    /**
     * Fill the context and the actor.
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
        $contribution->fillContext(['api_key' => self::SECRET, 'plan' => 'pro']);
        $contribution->fillActor(Reference::of(self::ACTOR_TYPE, self::ACTOR_ID));
    }
}
