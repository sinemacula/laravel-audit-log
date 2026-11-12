<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Symfony\Component\Uid\Uuid;

/**
 * An application's subclass of Symfony's UUID whose `__toString()` throws, so a
 * test fails if the value normaliser calls it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubUid extends Uuid
{
    /**
     * Fail the test if called.
     *
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function __toString(): never
    {
        throw new \LogicException('The normaliser called __toString().');
    }
}
