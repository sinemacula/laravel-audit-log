<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;

/**
 * The event mappers an application registers while it boots, each for an event
 * class or for a parent class or interface of the events it translates, with
 * the subtypes it leaves unmapped.
 *
 * An event is resolved to the mapping of its exact class, or else to the one
 * mapping of a parent class or interface it has; more than one is an ambiguity,
 * never a choice. A mapping skips an event that is any of its excepted subtypes
 * or a subtype of one. The answer for a class is worked out once and kept, so a
 * capture costs one lookup.
 *
 * The package's own events are never mapped: neither the marker they implement
 * nor any class implementing it is accepted. An identical registration changes
 * nothing, and any other second registration of a class or interface is
 * refused. It holds class names only and instantiates nothing, and once the
 * application has booted it is frozen and refuses any further registration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MapperRegistry
{
    /** @var array<class-string, array{mapper: class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>, except: list<class-string>}> Each mapping by the class or interface it is for, with its mapper and excepted subtypes. */
    private array $mappings = [];

    /** @var array<class-string, list<class-string>> The mappings that apply to each class resolved so far: the exact one alone, or every broad one. */
    private array $resolved = [];

    /** @var bool Whether the application has booted, after which nothing more is registered. */
    private bool $frozen = false;

    /**
     * Register the mapper for an event class or interface, leaving the subtypes
     * excepted unmapped. Registering the same mapper with the same subtypes, in
     * any order, changes nothing.
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
            self::refuse('Event mappers are registered while the application boots, and it has already booted.');
        }

        $mapped = self::mappable($classOrInterface);
        $mapper = self::mapper($mapper);
        $except = self::excepted($mapped, $except);

        $existing = $this->mappings[$mapped] ?? null;

        if ($existing !== null && $existing['mapper'] === $mapper && $existing['except'] === $except) {
            return;
        }

        if ($existing !== null) {
            self::refuse(sprintf('`%s` is already mapped differently; an event class or interface has one mapper.', $mapped));
        }

        $this->mappings[$mapped] = ['mapper' => $mapper, 'except' => $except];
        $this->resolved          = [];
    }

    /**
     * The mapper for an event of the class: its exact class's mapping, else the
     * one mapping of a parent class or interface that applies, and `null` when
     * none does.
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
     * Whether the registry refuses any further registration.
     *
     * @return bool
     */
    public function isFrozen(): bool
    {
        return $this->frozen;
    }

    /**
     * The mappings that apply to the class: its exact class's alone when it
     * applies, else every parent class or interface mapping that applies,
     * sorted.
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
     * Whether the mapping registered for the class or interface applies to an
     * event of the class: it exists and excepts none of the class's types.
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
     * The class or interface as PHP names it, refusing one that does not exist
     * and the package's own events.
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
     * The mapper class as PHP names it, refusing one that is not a class the
     * container can make that implements `EventMapper`.
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
     * The excepted subtypes as PHP names them, each once and sorted, refusing
     * one that does not exist or is not a subtype of the mapped class or
     * interface.
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
     * The class or interface's name as it was declared, so a name given in
     * another case is the same mapping, or `null` when it does not exist.
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

    /**
     * Refuse the registration.
     *
     * @param  string  $message
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuse(string $message): never
    {
        throw new \LogicException($message);
    }
}
