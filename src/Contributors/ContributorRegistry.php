<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contributors;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;

/**
 * The contributors every capture runs, by class name: the package's defaults,
 * then each one the application registers while it boots, once, in the order it
 * was registered.
 *
 * It holds names only and instantiates nothing, so a long-lived worker retains
 * no contributor: the recorder resolves each from the current container for
 * every capture. Once the application has booted the list is frozen and refuses
 * any further registration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContributorRegistry
{
    /** @var list<class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>> The package's contributors, which run first, in this order. */
    private const array DEFAULTS = [OriginContributor::class, RequestContributor::class, ActorContributor::class];

    /** @var list<class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>> The application's contributors, in the order they were registered. */
    private array $added = [];

    /** @var bool Whether the application has booted, after which nothing more is registered. */
    private bool $frozen = false;

    /**
     * Register a contributor by its class name. Registering one again, or a
     * default, changes nothing.
     *
     * @param  string  $class
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function add(string $class): void
    {
        if ($this->frozen) {
            throw new \LogicException('Contributors are registered while the application boots, and it has already booted.');
        }

        if (!class_exists($class) || !is_subclass_of($class, ContextContributor::class)) {
            throw new \InvalidArgumentException(sprintf('`%s` is not a class implementing `ContextContributor`.', $class));
        }

        if (in_array($class, $this->classes(), true)) {
            return;
        }

        $this->added[] = $class;
    }

    /**
     * The contributors a capture runs, in order: the defaults, then each one
     * registered.
     *
     * @return list<class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>>
     */
    public function classes(): array
    {
        return [...self::DEFAULTS, ...$this->added];
    }

    /**
     * Refuse any further registration: the application has booted. Freezing
     * again changes nothing.
     *
     * @return void
     */
    public function freeze(): void
    {
        $this->frozen = true;
    }

    /**
     * Whether the list refuses any further registration.
     *
     * @return bool
     */
    public function isFrozen(): bool
    {
        return $this->frozen;
    }
}
