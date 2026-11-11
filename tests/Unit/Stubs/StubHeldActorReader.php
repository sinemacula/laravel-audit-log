<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Auth\Guard;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Records\HeldActor;

/**
 * A held actor reader that gives a fixed actor, or refuses, and records the
 * guards it was asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubHeldActorReader implements HeldActorReader
{
    /** @var list<string> The guards it was asked about, in order. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\HeldActor  $held
     * @param  bool  $refuses
     */
    public function __construct(

        /** What it reads from any guard. */
        private readonly ?HeldActor $held = null,

        /** Whether it throws an `\InvalidArgumentException` instead. */
        private readonly bool $refuses = false,
    ) {}

    /**
     * The fixed actor, or a refusal.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Guard  $instance
     * @return ?\SineMacula\Laravel\AuditLog\Records\HeldActor
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function read(string $guard, Guard $instance): ?HeldActor
    {
        $this->asked[] = $guard;

        if ($this->refuses) {
            throw new \InvalidArgumentException('The guard holds no readable actor.');
        }

        return $this->held;
    }
}
