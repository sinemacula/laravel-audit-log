<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;

/**
 * Unit tests for a field reading: a sealed one holds a state and shows its
 * marker, and a revealed one holds and shows its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldReading::class)]
final class FieldReadingTest extends TestCase
{
    /**
     * A sealed reading holds its state and no value, and shows the state's
     * marker, for every state.
     *
     * @return void
     */
    public function testASealedReadingShowsItsMarker(): void
    {
        foreach (FieldState::cases() as $state) {
            $reading = FieldReading::sealed($state);

            self::assertSame($state, $reading->state, $state->value);
            self::assertNull($reading->value, $state->value);
            self::assertSame($state->marker(), $reading->display(), $state->value);
        }
    }

    /**
     * Rows of `[value]`: values a reader may reveal, `null` and an empty string
     * among them.
     *
     * @return iterable<string, array{0: array<string, string>|bool|float|int|string|null}>
     */
    public static function provideRevealedValues(): iterable
    {
        yield from [
            'a string'       => ['203.0.113.7'],
            'an empty one'   => [''],
            'an integer'     => [42],
            'a float'        => [1.5],
            'false'          => [false],
            'null'           => [null],
            'a map'          => [['number' => '4242']],
            'a marker alike' => ['[ENCRYPTED]'],
        ];
    }

    /**
     * A revealed reading holds its value and no state, and shows the value
     * exactly, even a falsy one or one that reads like a marker.
     *
     * @param  array<string, string>|bool|float|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideRevealedValues')]
    public function testARevealedReadingShowsItsValue(array|bool|float|int|string|null $value): void
    {
        $reading = FieldReading::revealed($value);

        self::assertNull($reading->state);
        self::assertSame($value, $reading->value);
        self::assertSame($value, $reading->display());
    }
}
