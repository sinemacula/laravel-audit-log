<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * The event definitions registered at boot, one per code, with the package's
 * own present from construction whatever the freeze.
 *
 * Whether registration is required is the caller's to say, so a malformed
 * setting never stops boot before `audit-log:check` reports it.
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
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function __construct()
    {
        foreach (PackageActivity::cases() as $activity) {
            $this->definitions[$activity->value] = $activity->definition();
        }
    }

    /**
     * Register a definition, or every case of a `DefinesAuditEvents` enum by
     * class name, all or none.
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
     * The code's registered definition, else the permissive default unless
     * registration is required.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @param  bool  $requireRegistered
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    public function definitionFor(EventCode $code, bool $requireRegistered = false): EventDefinition
    {
        if (isset($this->definitions[$code->value])) {
            return $this->definitions[$code->value];
        }

        if ($requireRegistered) {
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
     * Refuse any further registration; freezing again changes nothing.
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
     * The definitions of every case of the enum, refused unless it is a
     * string-backed `DefinesAuditEvents` enum whose cases each define their own
     * code.
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
