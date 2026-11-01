<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

use Illuminate\Database\Eloquent\Model;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Symfony\Component\Uid\AbstractUid;

/**
 * How a value given at capture becomes one a record can store, applied once,
 * the first matching rule winning: a model becomes its reference, never its
 * attributes or its JSON, and is checked first because a model is also
 * `Stringable` and `JsonSerializable`; a reference becomes its type and id; a
 * backed enum becomes its value and a unit enum its name; a date becomes
 * ISO-8601 UTC with microseconds; a UUID or ULID of one of its library's own
 * classes becomes its string, cleaned, and one of any other class
 * `[UNSERIALISABLE]`; booleans and `null` stay, and strings stay once cleaned;
 * an integer stays within the range every JSON reader keeps exactly and becomes
 * its decimal string beyond it; a finite float becomes its shortest round-trip
 * decimal string and a non-finite one `[NONFINITE]`; an array becomes a list or
 * a map; anything else becomes `[UNSERIALISABLE]`, never cast and never called,
 * so callers convert their own values.
 *
 * The outermost array is at depth 1, and an array deeper than 8 becomes
 * `[TRUNCATED]`, which also bounds a structure that refers to itself. Map keys
 * are cleaned; a key that, once cleaned, is already in its map keeps the first
 * value and is diagnosed by its schema path.
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

    /** @var string Separator of a schema path's segments. */
    private const string PATH_SEPARATOR = '.';

    /** @var string A list index's segment in a schema path. */
    private const string LIST_SEGMENT = '*';

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
    public static function normalise(mixed $value): Normalised
    {
        $collisions = [];
        $count      = 0;

        $normalised = self::value($value, 1, '', $collisions, $count);

        return new Normalised($normalised, $collisions, $count);
    }

    /**
     * The float as ECMAScript's `Number::toString` writes it: the fewest
     * significant digits that read back as the same float, written out in full
     * from 1e-6 to below 1e21 and as `d.ddde±n` otherwise, never reading the
     * `precision` or `serialize_precision` settings. Zero, negative zero
     * included, is `0`, and a non-finite float is `[NONFINITE]`.
     *
     * @param  float  $value
     * @return string
     */
    public static function float(float $value): string
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
     * @param  string  $path
     * @param  list<string>  $collisions
     * @param  int  $count
     * @return array<array-key, mixed>|bool|int|string|null
     *
     * @param-out list<string>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function value(mixed $value, int $depth, string $path, array &$collisions, int &$count): array|bool|int|string|null
    {
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
    private static function object(object $value): array|int|string
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
    private static function backed(\BackedEnum $value): int|string
    {
        return is_int($value->value) ? self::integer($value->value) : TextSanitizer::clean($value->value);
    }

    /**
     * The UUID or ULID's string, cleaned, when the object is one of its
     * library's own classes. Any other class, an application's subclass or an
     * anonymous one, can write anything and is never called, so it is
     * `[UNSERIALISABLE]`; the string is cleaned even so, since a library's own
     * class may still write through an application's codec.
     *
     * @param  \Ramsey\Uuid\UuidInterface|\Symfony\Component\Uid\AbstractUid  $value
     * @return string
     */
    private static function uid(AbstractUid|UuidInterface $value): string
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
    private static function scalar(mixed $value): bool|int|string|null
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
    private static function integer(int $value): int|string
    {
        return $value >= -self::MAX_SAFE_INTEGER && $value <= self::MAX_SAFE_INTEGER ? $value : (string) $value;
    }

    /**
     * The date as ISO-8601 in UTC with microseconds.
     *
     * @param  \DateTimeInterface  $value
     * @return string
     */
    private static function date(\DateTimeInterface $value): string
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
     * @param  string  $path
     * @param  list<string>  $collisions
     * @param  int  $count
     * @return array<array-key, mixed>|string
     *
     * @param-out list<string>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function collection(array $value, int $depth, string $path, array &$collisions, int &$count): array|string
    {
        if ($depth > self::MAX_DEPTH) {
            return self::TRUNCATED;
        }

        return array_is_list($value)
            ? self::list($value, $depth, $path, $collisions, $count)
            : self::map($value, $depth, $path, $collisions, $count);
    }

    /**
     * The list with each element normalised one level deeper, every index
     * written `*` in the path.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<mixed>  $value
     * @param  int  $depth
     * @param  string  $path
     * @param  list<string>  $collisions
     * @param  int  $count
     * @return list<mixed>
     *
     * @param-out list<string>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function list(array $value, int $depth, string $path, array &$collisions, int &$count): array
    {
        $path = self::path($path, self::LIST_SEGMENT);
        $list = [];

        foreach ($value as $element) {
            $list[] = self::value($element, $depth + 1, $path, $collisions, $count);
        }

        return $list;
    }

    /**
     * The map with each key cleaned and each value normalised one level
     * deeper; a key already present once cleaned keeps the first value and
     * is recorded as a collision.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $value
     * @param  int  $depth
     * @param  string  $path
     * @param  list<string>  $collisions
     * @param  int  $count
     * @return array<array-key, mixed>
     *
     * @param-out list<string>  $collisions
     *
     * @throws \InvalidArgumentException
     */
    private static function map(array $value, int $depth, string $path, array &$collisions, int &$count): array
    {
        $map = [];

        foreach ($value as $key => $element) {
            $key     = TextSanitizer::clean((string) $key);
            $keyPath = self::path($path, $key);

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
     * @param  string  $path
     * @param  list<string>  $collisions
     * @param  int  $count
     * @return void
     *
     * @param-out list<string>  $collisions
     */
    private static function collide(string $path, array &$collisions, int &$count): void
    {
        $count++;

        if (count($collisions) >= Normalised::MAX_COLLISIONS) {
            return;
        }

        $collisions[] = $path;
    }

    /**
     * The path of a segment beneath its parent's path.
     *
     * @param  string  $parent
     * @param  string  $segment
     * @return string
     */
    private static function path(string $parent, string $segment): string
    {
        return $parent === '' ? $segment : $parent . self::PATH_SEPARATOR . $segment;
    }

    /**
     * The fewest significant digits that read back as the positive finite
     * float, and the decimal exponent of the first. The values that read back
     * as the float form an interval around it, which holds a decimal of a given
     * length only if it holds the nearest one below the float or the nearest
     * one above; `%e` gives the nearer of the two, correctly rounded, so each
     * length is searched with those digits first and then, if they do not read
     * back, the next decimal up, a unit above them. The decimal a unit below
     * never needs trying: the interval reaches as far below the float as above
     * it, except at a power of two, where it reaches twice as far above, so
     * when the nearer decimal falls outside it the farther one below does too,
     * while the farther one above can be inside. `%e` is not locale-aware, and
     * 17 significant digits always read back, so the search ends by the
     * sixteenth place. The fewest digits never end in a zero, which would read
     * back with one digit fewer.
     *
     * @param  float  $value
     * @return array{0: string, 1: int}
     */
    private static function shortestDigits(float $value): array
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
    private static function readsBack(float $value, int $rounded, int $exponent, int $places): ?array
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
