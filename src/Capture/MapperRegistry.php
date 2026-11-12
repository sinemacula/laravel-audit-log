<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;

/**
 * The event mappers registered at boot, each for an event class, parent class
 * or interface, with the subtypes it leaves unmapped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MapperRegistry
{
    /** @var array<class-string, array{mapper: class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>, except: list<class-string>}> Each mapping by the class or interface it is for. */
    private array $mappings = [];

    /** @var array<class-string, list<class-string>> The mappings that apply to each class resolved so far. */
    private array $resolved = [];

    /** @var bool Whether the application has booted, after which nothing more is registered. */
    private bool $frozen = false;

    /**
     * Register the mapper for an event class or interface; an identical
     * registration changes nothing.
     *
     * @param  string  $classOrInterface
     * @param  string  $mapper
     * @param  list<string>  $except
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function map(string $classOrInterface, string $mapper, array $except = []): void
    {
        if ($this->frozen) {
            throw new \LogicException('Event mappers are registered while the application boots, and it has already booted.');
        }

        $mapped = self::mappable($classOrInterface);
        $mapper = self::mapper($mapper);
        $except = self::excepted($mapped, $except);

        $existing = $this->mappings[$mapped] ?? null;

        if ($existing !== null && $existing['mapper'] === $mapper && $existing['except'] === $except) {
            return;
        }

        if ($existing !== null) {
            throw new \LogicException(sprintf('`%s` is already mapped differently; an event class or interface has one mapper.', $mapped));
        }

        $this->mappings[$mapped] = ['mapper' => $mapper, 'except' => $except];
        $this->resolved          = [];
    }

    /**
     * The mapper for an event of the class, or `null` when no mapping applies.
     *
     * @param  class-string  $class
     * @return ?class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>
     *
     * @throws \LogicException
     */
    public function mapperFor(string $class): ?string
    {
        $applying = $this->resolved[$class] ??= $this->applyingTo($class);

        if (count($applying) > 1) {
            $mappings = implode(', ', array_map(static fn (string $mapping): string => '`' . $mapping . '`', $applying));

            throw new \LogicException(sprintf('`%s` matches several mappings: %s.', $class, $mappings));
        }

        return $applying === [] ? null : $this->mappings[$applying[0]]['mapper'];
    }

    /**
     * Whether any mapper is registered.
     *
     * @return bool
     */
    public function hasMappings(): bool
    {
        return $this->mappings !== [];
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
     * Whether the registry refuses any further registration.
     *
     * @return bool
     */
    public function isFrozen(): bool
    {
        return $this->frozen;
    }

    /**
     * The mappings that apply to the class: its exact class's alone, else every
     * applicable parent or interface mapping, sorted.
     *
     * @param  class-string  $class
     * @return list<class-string>
     */
    private function applyingTo(string $class): array
    {
        if ($this->applies($class, $class)) {
            return [$class];
        }

        $broad = array_values(array_filter(
            [...array_values(class_parents($class) ?: []), ...array_values(class_implements($class) ?: [])],
            fn (string $mapping): bool => $this->applies($mapping, $class),
        ));

        sort($broad);

        return $broad;
    }

    /**
     * Whether the mapping exists and excepts none of the class's types.
     *
     * @param  string  $mapping
     * @param  class-string  $class
     * @return bool
     */
    private function applies(string $mapping, string $class): bool
    {
        if (!isset($this->mappings[$mapping])) {
            return false;
        }

        foreach ($this->mappings[$mapping]['except'] as $excepted) {
            if (is_a($class, $excepted, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The class or interface as PHP names it, refusing a missing one and the
     * package's own events.
     *
     * @param  string  $classOrInterface
     * @return class-string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function mappable(string $classOrInterface): string
    {
        $mapped = self::declared($classOrInterface);

        if ($mapped === null) {
            throw new \InvalidArgumentException(sprintf('`%s` is not a class or an interface.', $classOrInterface));
        }

        if (is_a($mapped, AuditLogEvent::class, true)) {
            throw new \LogicException('The package\'s own events are never mapped.');
        }

        return $mapped;
    }

    /**
     * The mapper class as PHP names it, refusing one the container cannot make
     * or that does not implement `EventMapper`.
     *
     * @param  string  $mapper
     * @return class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>
     *
     * @throws \InvalidArgumentException
     */
    private static function mapper(string $mapper): string
    {
        $declared = self::declared($mapper);

        if ($declared === null || !is_subclass_of($declared, EventMapper::class) || !(new \ReflectionClass($declared))->isInstantiable()) {
            throw new \InvalidArgumentException(sprintf('`%s` is not a class implementing `EventMapper`.', $mapper));
        }

        return $declared;
    }

    /**
     * The excepted subtypes as PHP names them, deduplicated and sorted,
     * refusing any that is not a subtype of the mapping.
     *
     * @param  class-string  $mapped
     * @param  list<string>  $except
     * @return list<class-string>
     *
     * @throws \InvalidArgumentException
     */
    private static function excepted(string $mapped, array $except): array
    {
        $excepted = [];

        foreach ($except as $subtype) {
            $declared = self::declared($subtype);

            if ($declared === null || !is_subclass_of($declared, $mapped)) {
                $message = '`%s` is excepted from the mapping of `%s`, and is not a class or interface that extends or implements it.';

                throw new \InvalidArgumentException(sprintf($message, $subtype, $mapped));
            }

            $excepted[] = $declared;
        }

        $excepted = array_values(array_unique($excepted));

        sort($excepted);

        return $excepted;
    }

    /**
     * The name as declared, so another case is the same mapping, or `null` when
     * it does not exist.
     *
     * @param  string  $name
     * @return ?class-string
     */
    private static function declared(string $name): ?string
    {
        if (!class_exists($name) && !interface_exists($name)) {
            return null;
        }

        return (new \ReflectionClass($name))->getName();
    }
}
