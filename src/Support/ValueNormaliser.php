<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

use Illuminate\Database\Eloquent\Model;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Symfony\Component\Uid\AbstractUid;

/**
 * How a value given at capture becomes one a record can store, the first
 * matching rule winning. A model becomes its reference and is checked first,
 * since a model is also `Stringable` and `JsonSerializable`; anything
 * unsupported becomes `[UNSERIALISABLE]`, never cast or called.
 *
 * An array deeper than 8 becomes `[TRUNCATED]`, which also bounds a structure
 * that refers to itself. A map key that collides once cleaned keeps the first
 * value and is diagnosed by its raw path, which must be masked before it is
 * stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ValueNormaliser
{
    /** @var int Deepest array kept; deeper becomes TRUNCATED. */
    public const int MAX_DEPTH = 8;

    /** @var int 2^53 - 1: the largest integer every JSON reader keeps exactly. */
    public const int MAX_SAFE_INTEGER = 9007199254740991;

    /** @var string What a value of no supported type becomes. */
    public const string UNSERIALISABLE = '[UNSERIALISABLE]';

    /** @var string What a non-finite float becomes. */
    public const string NONFINITE = '[NONFINITE]';

    /** @var string What an array deeper than the deepest kept becomes. */
    public const string TRUNCATED = '[TRUNCATED]';

    /** @var int Point position (the exponent plus one) above which a float is written in exponential form. */
    private const int POSITIONAL_LIMIT = 21;

    /** @var int Point position (the exponent plus one) at or below which a float is written in exponential form. */
    private const int FRACTIONAL_LIMIT = -6;

    /** @var list<string> Namespaces of the UUID libraries whose own classes write their string. */
    private const array UID_NAMESPACES = ['Ramsey\Uuid\\', 'Symfony\Component\Uid\\'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The value normalised, with the diagnostics of the map keys that collided
     * once cleaned.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return \SineMacula\Laravel\AuditLog\Support\Normalised
     *
     * @throws \InvalidArgumentException
     */
    public static function normalise(#[\SensitiveParameter] mixed $value): Normalised
    {
        $collisions = [];
        $count      = 0;

        $normalised = self::value($value, 1, [], $collisions, $count);

        return new Normalised($normalised, $collisions, $count);
    }

    /**
     * The float as ECMAScript's `Number::toString` writes it, never reading
     * `precision` or `serialize_precision`; negative zero is `0`, and a
     * non-finite float `[NONFINITE]`.
     *
     * @param  float  $value
     * @return string
     */
    public static function float(#[\SensitiveParameter] float $value): string
    {
        if (!is_finite($value)) {
            return self::NONFINITE;
        }

        [$digits, $exponent] = self::shortestDigits(abs($value));

        return ($value < 0 ? '-' : '') . self::written($digits, $exponent);
    }

    /**
     * The value normalised at its depth, an array here being at that depth,
     * with each collision recorded under the path given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @param  list<int|string>  $path
     * @param  list<list<int|string>>  $collisions
     * @param  int  $count
     * @return array<array-key, mixed>|bool|int|string|null
     *
     * @param-out list<list<int|string>>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function value(
        #[\SensitiveParameter] mixed $value,
        int $depth,
        #[\SensitiveParameter] array $path,
        #[\SensitiveParameter] array &$collisions,
        int &$count,
    ): array|bool|int|string|null {
        if (is_array($value)) {
            return self::collection($value, $depth, $path, $collisions, $count);
        }

        if (is_object($value)) {
            return self::object($value);
        }

        return self::scalar($value);
    }

    /**
     * The object normalised by the first object rule it matches, or
     * `[UNSERIALISABLE]` when it matches none.
     *
     * @param  object  $value
     * @return array{type: string, id: string}|int|string
     *
     * @throws \InvalidArgumentException
     */
    private static function object(#[\SensitiveParameter] object $value): array|int|string
    {
        return match (true) {
            $value instanceof Model                                        => Reference::to($value)->toArray(),
            $value instanceof Reference                                    => $value->toArray(),
            $value instanceof \BackedEnum                                  => self::backed($value),
            $value instanceof \UnitEnum                                    => $value->name,
            $value instanceof \DateTimeInterface                           => self::date($value),
            $value instanceof UuidInterface, $value instanceof AbstractUid => self::uid($value),
            default                                                        => self::UNSERIALISABLE,
        };
    }

    /**
     * The backed enum's value: a string cleaned, or an integer kept within the
     * safe range.
     *
     * @param  \BackedEnum  $value
     * @return int|string
     */
    private static function backed(#[\SensitiveParameter] \BackedEnum $value): int|string
    {
        return is_int($value->value) ? self::integer($value->value) : TextSanitizer::clean($value->value);
    }

    /**
     * The UUID or ULID's string, cleaned, from one of its library's own classes
     * only; any other class could write anything, so it is never called.
     *
     * @param  \Ramsey\Uuid\UuidInterface|\Symfony\Component\Uid\AbstractUid  $value
     * @return string
     */
    private static function uid(#[\SensitiveParameter] AbstractUid|UuidInterface $value): string
    {
        $class = $value::class;

        foreach (self::UID_NAMESPACES as $namespace) {
            if (str_starts_with($class, $namespace) && !str_contains($class, '@')) {
                return TextSanitizer::clean($value->toString());
            }
        }

        return self::UNSERIALISABLE;
    }

    /**
     * The scalar normalised: a string cleaned, an integer kept within the safe
     * range, a float written as its shortest round-trip string, a boolean or
     * `null` as it is, and anything else, a resource, open or closed,
     * `[UNSERIALISABLE]`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return bool|int|string|null
     */
    private static function scalar(#[\SensitiveParameter] mixed $value): bool|int|string|null
    {
        return match (true) {
            is_string($value)                => TextSanitizer::clean($value),
            is_int($value)                   => self::integer($value),
            is_float($value)                 => self::float($value),
            is_bool($value), $value === null => $value,
            default                          => self::UNSERIALISABLE,
        };
    }

    /**
     * The integer as it is within the safe range, or as its decimal string
     * beyond it.
     *
     * @param  int  $value
     * @return int|string
     */
    private static function integer(#[\SensitiveParameter] int $value): int|string
    {
        return $value >= -self::MAX_SAFE_INTEGER && $value <= self::MAX_SAFE_INTEGER ? $value : (string) $value;
    }

    /**
     * The date as ISO-8601 in UTC with microseconds.
     *
     * @param  \DateTimeInterface  $value
     * @return string
     */
    private static function date(#[\SensitiveParameter] \DateTimeInterface $value): string
    {
        return \DateTimeImmutable::createFromInterface($value)
            ->setTimezone(new \DateTimeZone('UTC'))
            ->format('Y-m-d\TH:i:s.u\Z');
    }

    /**
     * The array normalised at its depth: `[TRUNCATED]` beyond the deepest kept,
     * otherwise a list or a map of its normalised elements.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $value
     * @param  int  $depth
     * @param  list<int|string>  $path
     * @param  list<list<int|string>>  $collisions
     * @param  int  $count
     * @return array<array-key, mixed>|string
     *
     * @param-out list<list<int|string>>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function collection(
        #[\SensitiveParameter] array $value,
        int $depth,
        #[\SensitiveParameter] array $path,
        #[\SensitiveParameter] array &$collisions,
        int &$count,
    ): array|string {
        if ($depth > self::MAX_DEPTH) {
            return self::TRUNCATED;
        }

        return array_is_list($value)
            ? self::list($value, $depth, $path, $collisions, $count)
            : self::map($value, $depth, $path, $collisions, $count);
    }

    /**
     * The list with each element normalised one level deeper, its index the
     * next segment of the element's path.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<mixed>  $value
     * @param  int  $depth
     * @param  list<int|string>  $path
     * @param  list<list<int|string>>  $collisions
     * @param  int  $count
     * @return list<mixed>
     *
     * @param-out list<list<int|string>>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function list(#[\SensitiveParameter] array $value, int $depth, #[\SensitiveParameter] array $path, #[\SensitiveParameter] array &$collisions, int &$count): array
    {
        $list = [];

        foreach ($value as $index => $element) {
            $list[] = self::value($element, $depth + 1, array_merge($path, [$index]), $collisions, $count);
        }

        return $list;
    }

    /**
     * The map with each key cleaned and each value normalised one level
     * deeper; a key already present once cleaned keeps the first value and is
     * recorded as a collision.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $value
     * @param  int  $depth
     * @param  list<int|string>  $path
     * @param  list<list<int|string>>  $collisions
     * @param  int  $count
     * @return array<array-key, mixed>
     *
     * @param-out list<list<int|string>>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function map(#[\SensitiveParameter] array $value, int $depth, #[\SensitiveParameter] array $path, #[\SensitiveParameter] array &$collisions, int &$count): array
    {
        $map = [];

        foreach ($value as $key => $element) {
            $key     = TextSanitizer::clean((string) $key);
            $keyPath = array_merge($path, [$key]);

            if (array_key_exists($key, $map)) {
                self::collide($keyPath, $collisions, $count);

                continue;
            }

            $map[$key] = self::value($element, $depth + 1, $keyPath, $collisions, $count);
        }

        return $map;
    }

    /**
     * Record a collision: its path while fewer than the most are kept, and
     * always in the count.
     *
     * @param  list<int|string>  $path
     * @param  list<list<int|string>>  $collisions
     * @param  int  $count
     * @return void
     *
     * @param-out list<list<int|string>>  $collisions
     */
    private static function collide(#[\SensitiveParameter] array $path, #[\SensitiveParameter] array &$collisions, int &$count): void
    {
        $count++;

        if (count($collisions) >= Normalised::MAX_COLLISIONS) {
            return;
        }

        $collisions[] = $path;
    }

    /**
     * The fewest significant digits that read back as the positive finite
     * float, and the decimal exponent of the first.
     *
     * `%e` gives the nearest decimal at each length, and only it or the one a
     * unit above can read back, since the rounding interval never reaches
     * farther below the float than above; 17 digits always read back.
     *
     * @param  float  $value
     * @return array{0: string, 1: int}
     */
    private static function shortestDigits(#[\SensitiveParameter] float $value): array
    {
        $places = 0;

        do {
            [$mantissa, $exponent] = explode('e', sprintf('%.' . $places . 'e', $value));

            $found = self::readsBack($value, (int) str_replace('.', '', $mantissa), (int) $exponent, $places);

            $places++;
        } while ($found === null);

        return $found;
    }

    /**
     * Of `%e`'s rounded significand, written with the places given after the
     * first digit at the exponent given, and the significand a unit above it,
     * the first that reads back as the float, as its digits and the decimal
     * exponent of the first, or `null` when neither does.
     *
     * @param  float  $value
     * @param  int  $rounded
     * @param  int  $exponent
     * @param  int  $places
     * @return ?array{0: string, 1: int}
     */
    private static function readsBack(#[\SensitiveParameter] float $value, int $rounded, int $exponent, int $places): ?array
    {
        $scale = $exponent - $places;

        foreach ([$rounded, $rounded + 1] as $significand) {
            if ((float) ($significand . 'e' . $scale) === $value) {
                $digits = (string) $significand;

                return [$digits, $scale + strlen($digits) - 1];
            }
        }

        return null;
    }

    /**
     * The digits, the first of them at the decimal exponent given, written as
     * ECMAScript writes a number: in exponential form when the decimal point
     * would fall beyond the positional range, and in full within it.
     *
     * @param  string  $digits
     * @param  int  $exponent
     * @return string
     */
    private static function written(string $digits, int $exponent): string
    {
        $point = $exponent + 1;

        if ($point > self::POSITIONAL_LIMIT || $point <= self::FRACTIONAL_LIMIT) {
            return self::exponential($digits, $exponent);
        }

        return self::positional($digits, $point);
    }

    /**
     * The digits written in full, the decimal point falling after the given
     * count of digits: zeros added up to the point, the point among the digits,
     * or the digits after a point and leading zeros.
     *
     * @param  string  $digits
     * @param  int  $point
     * @return string
     */
    private static function positional(string $digits, int $point): string
    {
        if ($point <= 0) {
            return '0.' . str_repeat('0', -$point) . $digits;
        }

        $count = strlen($digits);

        return $point >= $count
            ? $digits . str_repeat('0', $point - $count)
            : substr($digits, 0, $point) . '.' . substr($digits, $point);
    }

    /**
     * The digits written in exponential form: the first digit, the rest after a
     * point when there are any, then the signed exponent.
     *
     * @param  string  $digits
     * @param  int  $exponent
     * @return string
     */
    private static function exponential(string $digits, int $exponent): string
    {
        $fraction = strlen($digits) > 1 ? '.' . substr($digits, 1) : '';

        return $digits[0] . $fraction . sprintf('e%+d', $exponent);
    }
}
