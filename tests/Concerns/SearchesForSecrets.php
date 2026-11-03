<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Container\Container;
use PHPUnit\Framework\Test;

/**
 * Searches anything a capture left behind for a planted secret: arrays and
 * their keys, public and private properties by reflection, what a closure
 * holds, and what a throwable holds: its message, its previous chain, its trace
 * as a string and the scalar and array arguments of its frames.
 *
 * It does not descend into a container or a PHPUnit object: a delivery
 * closure's `$this` reaches the whole application, and the walk would be slow
 * and would find the test's own values. A `\SensitiveParameterValue` is what a
 * marked parameter leaves in a frame, so what it wraps is withheld by design
 * and never searched. An object passed straight to a frame is not searched
 * either, since a trace writes it as its class alone.
 *
 * A failure names where the search looked and never prints what it found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SearchesForSecrets
{
    /** @var string The value a test plants and then searches for. */
    protected const string SECRET = 's3cr3t';

    /**
     * Fail, naming where the search looked, when the haystack holds the planted
     * secret anywhere the search reaches.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $haystack
     * @param  string  $where
     * @return void
     */
    protected static function assertHoldsNoSecret(mixed $haystack, string $where): void
    {
        self::assertFalse(self::holdsText($haystack, self::SECRET), sprintf('The planted secret was found in %s.', $where));
    }

    /**
     * Whether the haystack holds the text, in any case, anywhere the search
     * reaches, so a test can show the search reached what it claims to clear.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $haystack
     * @param  string  $text
     * @return bool
     */
    protected static function holdsText(mixed $haystack, string $text): bool
    {
        $visited = [];

        return self::isFoundIn($haystack, $text, $visited);
    }

    /**
     * Whether the text is in the value, each object being searched once. An
     * object is kept in the visited set so that its id cannot be reused while
     * the search runs.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $text
     * @param  array<int, object>  $visited
     * @return bool
     */
    private static function isFoundIn(mixed $value, string $text, array &$visited): bool
    {
        if (is_array($value)) {
            return self::isFoundInArray($value, $text, $visited);
        }

        if (!is_object($value)) {
            return is_scalar($value) && stripos((string) $value, $text) !== false;
        }

        if (isset($visited[spl_object_id($value)]) || self::isSealed($value)) {
            return false;
        }

        $visited[spl_object_id($value)] = $value;

        return self::isFoundInArray(self::partsOf($value), $text, $visited);
    }

    /**
     * Whether the text is in one of the array's keys or elements.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  string  $text
     * @param  array<int, object>  $visited
     * @return bool
     */
    private static function isFoundInArray(array $values, string $text, array &$visited): bool
    {
        foreach ($values as $key => $value) {
            if (self::isFoundIn((string) $key, $text, $visited) || self::isFoundIn($value, $text, $visited)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the search stops at the object: a container, anything of PHPUnit,
     * and what a marked parameter leaves in a frame.
     *
     * @param  object  $value
     * @return bool
     */
    private static function isSealed(object $value): bool
    {
        return $value instanceof Container
            || $value instanceof Test
            || $value instanceof \SensitiveParameterValue
            || str_starts_with($value::class, 'PHPUnit\\');
    }

    /**
     * What the object holds, for the kind of object it is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  object  $value
     * @return array<array-key, mixed>
     */
    private static function partsOf(object $value): array
    {
        return match (true) {
            $value instanceof \Closure   => self::partsOfClosure($value),
            $value instanceof \Throwable => self::partsOfThrowable($value),
            $value instanceof \ArrayObject,
            $value instanceof \SplObjectStorage,
            $value instanceof \WeakMap => [iterator_to_array(self::entriesOf($value), false), self::propertiesOf($value)],
            default                    => self::propertiesOf($value),
        };
    }

    /**
     * What a closure holds: the object it is bound to and the variables it
     * uses.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $closure
     * @return array<array-key, mixed>
     */
    private static function partsOfClosure(\Closure $closure): array
    {
        $function = new \ReflectionFunction($closure);

        return [$function->getClosureThis(), $function->getClosureUsedVariables()];
    }

    /**
     * What a throwable holds: its message, its previous chain, its trace as a
     * string, the scalar and array arguments of its frames, and the properties
     * of its own class.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Throwable  $throwable
     * @return array<array-key, mixed>
     */
    private static function partsOfThrowable(\Throwable $throwable): array
    {
        $arguments = [];

        foreach ($throwable->getTrace() as $frame) {
            foreach ($frame['args'] ?? [] as $argument) {
                $arguments[] = is_object($argument) ? null : $argument;
            }
        }

        return [$throwable->getMessage(), $throwable->getTraceAsString(), $throwable->getPrevious(), $arguments, self::propertiesOf($throwable)];
    }

    /**
     * The entries of one of the collections PHP keeps out of its properties,
     * each entry a key and an element.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \ArrayObject<array-key, mixed>|\SplObjectStorage<object, mixed>|\WeakMap<object, mixed>  $collection
     * @return \Generator<int, list<mixed>>
     */
    private static function entriesOf(\ArrayObject|\SplObjectStorage|\WeakMap $collection): \Generator
    {
        foreach ($collection as $key => $element) {
            yield [$key, $element, $collection instanceof \SplObjectStorage ? $collection[$element] : null];
        }
    }

    /**
     * The initialised instance properties of the object, public and private,
     * dynamic ones and those its parents declare included. A throwable's base
     * class is left out, since its own parts are read through its methods.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  object  $value
     * @return list<mixed>
     */
    private static function propertiesOf(object $value): array
    {
        $properties = [];

        for ($class = new \ReflectionObject($value); $class !== false && !in_array($class->name, [\Exception::class, \Error::class], true); $class = $class->getParentClass()) {
            foreach ($class->getProperties() as $property) {
                if ($property->class !== $class->name || $property->isStatic() || !$property->isInitialized($value)) {
                    continue;
                }

                $properties[] = $property->getValue($value);
            }
        }

        return $properties;
    }
}
