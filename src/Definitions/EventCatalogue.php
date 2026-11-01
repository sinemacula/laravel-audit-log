<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * The event definitions an application registers while it boots, one per code,
 * and the definition every code is recorded under.
 *
 * A definition is registered on its own or as every case of an enum defining
 * the application's codes; an enum is registered whole or, when any of its
 * cases is refused, not at all. Registering an identical definition again
 * changes nothing, and a different one for a registered code is refused,
 * whichever came first. Once the application has booted the catalogue is frozen
 * and refuses any further registration, so a long-lived worker never registers
 * twice. A code no definition registers takes the permissive default, or is
 * refused when registration is required.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EventCatalogue
{
    /** @var array<string, \SineMacula\Laravel\AuditLog\Definitions\EventDefinition> The registered definitions, by code. */
    private array $definitions = [];

    /** @var bool Whether the application has booted, after which nothing more is registered. */
    private bool $frozen = false;

    /**
     * Constructor.
     *
     * @param  bool  $requireRegistered
     */
    public function __construct(

        /** Whether a code no definition registers is a programming error (`definitions.require_registered`). */
        private readonly bool $requireRegistered = false,
    ) {}

    /**
     * Register a definition, or every case of an enum implementing
     * `DefinesAuditEvents`, given by its class name. Every check runs before
     * anything is registered, so a refused enum registers none of its cases.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition|string  $definition
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function define(EventDefinition|string $definition): void
    {
        $this->refuseWhenFrozen();

        $definitions = is_string($definition) ? self::definitionsOf($definition) : [$definition];

        foreach ($definitions as $each) {
            $this->refuseConflicting($each);
        }

        foreach ($definitions as $each) {
            $this->definitions[$each->code] ??= $each;
        }
    }

    /**
     * The definition the code is recorded under: the registered one, or the
     * permissive default (version 1, the `general` category, every field
     * retained) when none is, unless registration is required.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    public function definitionFor(EventCode $code): EventDefinition
    {
        if (isset($this->definitions[$code->value])) {
            return $this->definitions[$code->value];
        }

        if ($this->requireRegistered) {
            throw new \InvalidArgumentException(sprintf('The event code `%s` is not registered, and unregistered codes are refused.', $code->value));
        }

        return EventDefinition::permissive($code);
    }

    /**
     * Whether a definition is registered for the code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @return bool
     */
    public function isRegistered(EventCode $code): bool
    {
        return isset($this->definitions[$code->value]);
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
     * Whether the catalogue refuses any further registration.
     *
     * @return bool
     */
    public function isFrozen(): bool
    {
        return $this->frozen;
    }

    /**
     * Refuse any registration once the application has booted.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseWhenFrozen(): void
    {
        if ($this->frozen) {
            throw new \LogicException('Event definitions are registered while the application boots, and it has already booted.');
        }
    }

    /**
     * Refuse a definition for a code that is registered with a different one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseConflicting(EventDefinition $definition): void
    {
        $registered = $this->definitions[$definition->code] ?? null;

        if ($registered !== null && !$registered->equals($definition)) {
            throw new \LogicException(sprintf('The event code `%s` is already defined differently; a code has one definition.', $definition->code));
        }
    }

    /**
     * The definitions of every case of the enum: refused unless it implements
     * `DefinesAuditEvents` and is backed by strings, checked before any case is
     * asked for its definition, and unless each case defines its own code.
     *
     * @param  string  $class
     * @return list<\SineMacula\Laravel\AuditLog\Definitions\EventDefinition>
     *
     * @throws \InvalidArgumentException
     */
    private static function definitionsOf(string $class): array
    {
        if (!enum_exists($class) || !is_subclass_of($class, DefinesAuditEvents::class)) {
            throw new \InvalidArgumentException(sprintf('`%s` is not an enum implementing `DefinesAuditEvents`.', $class));
        }

        if ((string) (new \ReflectionEnum($class))->getBackingType() !== 'string') {
            throw new \InvalidArgumentException('An event code enum must be backed by strings.');
        }

        $definitions = [];

        foreach ($class::cases() as $case) {
            $definition = $case->definition();

            if ($definition->code !== $case->value) {
                throw new \InvalidArgumentException(sprintf('`%s::%s` defines another event code.', $class, $case->name));
            }

            $definitions[] = $definition;
        }

        return $definitions;
    }
}
