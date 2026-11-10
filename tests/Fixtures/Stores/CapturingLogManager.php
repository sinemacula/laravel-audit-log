<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Stores;

use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Monolog\Handler\HandlerInterface;
use Monolog\Handler\NullHandler;
use Monolog\Logger as Monolog;

/**
 * A log manager that adds one capturing handler behind every channel's own, so
 * a channel whose handler fails captures nothing, as nothing was written, and a
 * stack, which takes its members' handlers, holds it once. A `NullHandler`
 * stops a record going further without writing it, so the capture goes ahead of
 * one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CapturingLogManager extends LogManager
{
    /** @var ?\Monolog\Handler\HandlerInterface The handler added behind every channel's. */
    private ?HandlerInterface $capturing = null;

    /**
     * Use the handler for every channel resolved from here on.
     *
     * @param  \Monolog\Handler\HandlerInterface  $capturing
     * @return void
     */
    public function captureWith(HandlerInterface $capturing): void
    {
        $this->capturing = $capturing;
    }

    /**
     * Resolve the channel, then put the capturing handler behind its own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $name
     * @param  ?array<array-key, mixed>  $config
     * @return \Psr\Log\LoggerInterface
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    protected function get(mixed $name, ?array $config = null)
    {
        if ($name !== null && !is_string($name)) {
            throw new \InvalidArgumentException('A log channel is named by a string.');
        }

        $logger = parent::get($name, $config);
        $inner  = $logger instanceof Logger ? $logger->getLogger() : $logger;

        if ($this->capturing !== null && $inner instanceof Monolog) {
            $own   = array_filter($inner->getHandlers(), fn (HandlerInterface $handler): bool => $handler !== $this->capturing);
            $nulls = array_filter($own, static fn (HandlerInterface $handler): bool => $handler instanceof NullHandler);

            $inner->setHandlers([...array_values(array_diff_key($own, $nulls)), $this->capturing, ...array_values($nulls)]);
        }

        return $logger;
    }
}
