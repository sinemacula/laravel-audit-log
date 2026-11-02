<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;

/**
 * An application's contributor filling an address that is not one, so a test
 * can see that it costs the record nothing but the address.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GarbageIpContributor implements ContextContributor
{
    /** @var string The address it fills. */
    public const string GARBAGE = "garbage\0garbage";

    /**
     * Fill the address.
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
        $contribution->fillClient(self::GARBAGE, null);
    }
}
