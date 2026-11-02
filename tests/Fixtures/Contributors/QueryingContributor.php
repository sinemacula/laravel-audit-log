<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Contributors;

use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;

/**
 * An application's contributor that runs one read of its own, at its own cost:
 * the package's query budgets cover its default contributors only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class QueryingContributor implements ContextContributor
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

        /** The connections it reads from. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Run one read, and fill the context with the fact.
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
        $this->connections->connection()->select('select 1');

        $contribution->fillContext(['queried' => true]);
    }
}
