<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;

/**
 * Unit tests for the source settings: a configured id kept as given, the slug
 * of the application's name in its place, how that slug is cut and when it
 * fails closed, the optional region, and the values no message ever shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SourceSettings::class)]
final class SourceSettingsTest extends TestCase
{
    /** @var string The refusal of a malformed source id. */
    private const string MALFORMED_ID = '`audit-log.source.id` must be from 1 to 64 characters, with no control characters.';

    /** @var string The refusal of an application name that gives no slug. */
    private const string NO_SLUG = '`audit-log.source.id` must be set, because `app.name` gives no slug.';

    /** @var string The refusal of a malformed region. */
    private const string MALFORMED_REGION = '`audit-log.source.region` must be null or empty, or from 1 to 32 characters, with no control characters.';

    /**
     * A configured id is validated and kept exactly as given, never slugged,
     * whatever `app.name` is.
     *
     * @return void
     */
    public function testAConfiguredIdIsKeptAsGiven(): void
    {
        self::assertSame('Billing Service (EU)', self::settings(['id' => 'Billing Service (EU)'], 'Acme Billing')->id());
        self::assertSame('Billing Service (EU)', self::settings(['id' => 'Billing Service (EU)'], null)->id());
    }

    /**
     * Rows of `[id]`: the length's bound, in single-byte and in multi-byte
     * characters, which a limit counted in bytes would refuse.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIdsAtTheBound(): iterable
    {
        yield from [
            'one character'            => ['a'],
            '64 characters'            => [str_repeat('a', 64)],
            '64 multi-byte characters' => [str_repeat('é', 64)],
        ];
    }

    /**
     * An id from 1 to 64 characters is kept.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideIdsAtTheBound')]
    public function testKeepsAnIdUpToTheColumn(string $id): void
    {
        self::assertSame($id, self::settings(['id' => $id])->id());
    }

    /**
     * With no id configured, or a `null` one, the id is a slug of `app.name`.
     *
     * @return void
     */
    public function testNoIdTakesASlugOfTheApplicationName(): void
    {
        self::assertSame('acme-billing', self::settings([], 'Acme Billing')->id());
        self::assertSame('acme-billing', self::settings(['id' => null], 'Acme Billing')->id());
    }

    /**
     * An empty id, which an empty environment line gives, reads as none.
     *
     * @return void
     */
    public function testAnEmptyIdTakesTheSlugToo(): void
    {
        self::assertSame('acme-billing', self::settings(['id' => ''], 'Acme Billing')->id());
    }

    /**
     * The slug is ASCII whatever the name's script, so the column holds the
     * same id on every engine, and a name past the column in multi-byte
     * characters is cut like any other.
     *
     * @return void
     */
    public function testTheSlugTransliteratesTheApplicationName(): void
    {
        self::assertSame('zurich-buro', self::settings([], 'Zürich Büro')->id());
        self::assertSame(str_repeat('e', 64), self::settings([], str_repeat('é', 65))->id());
    }

    /**
     * An application name past the column is cut to 64 characters, and one that
     * slugs to exactly 64 is kept whole.
     *
     * @return void
     */
    public function testTheSlugIsCutTo64Characters(): void
    {
        self::assertSame(str_repeat('a', 64), self::settings([], str_repeat('a', 65))->id());
        self::assertSame(str_repeat('a', 64), self::settings([], str_repeat('a', 64))->id());
    }

    /**
     * A cut that falls just after a separator leaves no hyphen at the end of
     * the id.
     *
     * @return void
     */
    public function testACutSlugEndsWithoutAHyphen(): void
    {
        self::assertSame(str_repeat('a', 63), self::settings([], str_repeat('a', 63) . ' billing')->id());
    }

    /**
     * Rows of `[application name]`: names that are no strings, or that hold
     * nothing a slug keeps.
     *
     * @return iterable<string, array{0: int|string|null}>
     */
    public static function provideNamesWithNoSlug(): iterable
    {
        yield from [
            'only punctuation'         => ['!!!'],
            'only separators'          => ['- -'],
            'only an emoji'            => ['🚀'],
            'nothing to transliterate' => ['日本語'],
            'an empty name'            => [''],
            'an integer'               => [42],
            'a null name'              => [null],
        ];
    }

    /**
     * An application name that gives no slug fails closed, so a record never
     * has a source nobody chose.
     *
     * @param  int|string|null  $name
     * @return void
     */
    #[DataProvider('provideNamesWithNoSlug')]
    public function testAnApplicationNameThatSlugsToNothingFailsClosed(int|string|null $name): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::NO_SLUG);

        self::settings([], $name)->id();
    }

    /**
     * With no `app.name` key at all there is no slug either: a missing key has
     * no default to fall back on.
     *
     * @return void
     */
    public function testAMissingApplicationNameFailsClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::NO_SLUG);

        (new SourceSettings(new Repository))->id();
    }

    /**
     * Rows of `[id]`: other types, including falsy values that must not read as
     * no id, one character past the column, in single-byte and multi-byte
     * characters, and text cleaning would change.
     *
     * @return iterable<string, array{0: array<never, never>|bool|int|string}>
     */
    public static function provideMalformedIds(): iterable
    {
        yield from [
            'an integer'               => [42],
            'zero'                     => [0],
            'true'                     => [true],
            'false'                    => [false],
            'an array'                 => [[]],
            '65 characters'            => [str_repeat('a', 65)],
            '65 multi-byte characters' => [str_repeat('é', 65)],
            'a control character'      => ["billing\x01service"],
            'a line feed'              => ["billing\n"],
            'invalid UTF-8'            => ["billing\xFF"],
        ];
    }

    /**
     * Each malformed id fails closed and never falls back to the slug, which
     * would hide the mistake behind a source nobody chose.
     *
     * @param  array<never, never>|bool|int|string  $id
     * @return void
     */
    #[DataProvider('provideMalformedIds')]
    public function testRefusesEachMalformedId(array|bool|int|string $id): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED_ID);

        self::settings(['id' => $id], 'Acme Billing')->id();
    }

    /**
     * With no region configured, or a `null` one, there is none.
     *
     * @return void
     */
    public function testRegionDefaultsToNone(): void
    {
        self::assertNull(self::settings([])->region());
        self::assertNull(self::settings(['region' => null])->region());
    }

    /**
     * An empty region, which an empty environment line gives, reads as none.
     *
     * @return void
     */
    public function testAnEmptyRegionIsNone(): void
    {
        self::assertNull(self::settings(['region' => ''])->region());
    }

    /**
     * Rows of `[region]`: an ordinary one and the length's bounds, in
     * single-byte and in multi-byte characters.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRegions(): iterable
    {
        yield from [
            'an ordinary region'       => ['eu-west-1'],
            'one character'            => ['a'],
            '32 characters'            => [str_repeat('a', 32)],
            '32 multi-byte characters' => [str_repeat('é', 32)],
        ];
    }

    /**
     * A configured region is kept as given.
     *
     * @param  string  $region
     * @return void
     */
    #[DataProvider('provideRegions')]
    public function testAConfiguredRegionIsKept(string $region): void
    {
        self::assertSame($region, self::settings(['region' => $region])->region());
    }

    /**
     * Rows of `[region]`: other types, including falsy values that must not
     * read as none, one character past the column, in single-byte and
     * multi-byte characters, and text cleaning would change.
     *
     * @return iterable<string, array{0: array<never, never>|bool|int|string}>
     */
    public static function provideMalformedRegions(): iterable
    {
        yield from [
            'an integer'               => [42],
            'zero'                     => [0],
            'true'                     => [true],
            'false'                    => [false],
            'an array'                 => [[]],
            '33 characters'            => [str_repeat('a', 33)],
            '33 multi-byte characters' => [str_repeat('é', 33)],
            'a control character'      => ["eu\x01west"],
            'a line feed'              => ["eu-west\n"],
            'invalid UTF-8'            => ["eu\xFF"],
        ];
    }

    /**
     * Each malformed region fails closed.
     *
     * @param  array<never, never>|bool|int|string  $region
     * @return void
     */
    #[DataProvider('provideMalformedRegions')]
    public function testRefusesEachMalformedRegion(array|bool|int|string $region): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED_REGION);

        self::settings(['region' => $region])->region();
    }

    /**
     * `validate()` reads both settings: it passes when both are well formed,
     * and fails on either, the id's fallback to the slug included.
     *
     * @return void
     */
    public function testValidateReadsBoth(): void
    {
        self::settings(['id' => 'billing', 'region' => 'eu-west-1'])->validate();
        self::settings([], 'Acme Billing')->validate();

        $refusals = [
            self::MALFORMED_ID     => self::settings(['id' => 42, 'region' => 'eu-west-1']),
            self::NO_SLUG          => self::settings(['region' => 'eu-west-1'], '!!!'),
            self::MALFORMED_REGION => self::settings(['id' => 'billing', 'region' => 42]),
        ];

        foreach ($refusals as $message => $settings) {
            try {
                $settings->validate();
                self::fail('Expected the settings to be refused: ' . $message);
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[source settings, the application's name, the value]`: each
     * refusal, given a value a message could repeat.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string, 2: string}>
     */
    public static function provideRefusedValues(): iterable
    {
        $long    = 'leaked' . str_repeat('x', 100);
        $control = "leaked\x01value";

        yield from [
            'a long id'              => [['id' => $long], 'Acme Billing', $long],
            'an id with controls'    => [['id' => $control], 'Acme Billing', 'leaked'],
            'a long region'          => [['id' => 'billing', 'region' => $long], 'Acme Billing', $long],
            'a region with controls' => [['id' => 'billing', 'region' => $control], 'Acme Billing', 'leaked'],
            'a name with no slug'    => [[], '!!!', '!!!'],
        ];
    }

    /**
     * No refusal repeats the value it refuses, so a setting mistyped with
     * something sensitive never reaches a log.
     *
     * @param  array<string, string>  $source
     * @param  string  $name
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testNoMessageHoldsTheValue(array $source, string $name, string $value): void
    {
        try {
            self::settings($source, $name)->validate();
            self::fail('Expected the value to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString($value, $exception->getMessage());
        }
    }

    /**
     * The settings over the given `audit-log.source` configuration and
     * `app.name`.
     *
     * @param  array<string, array<never, never>|bool|int|string|null>  $source
     * @param  int|string|null  $name
     * @return \SineMacula\Laravel\AuditLog\Records\SourceSettings
     */
    private static function settings(array $source, int|string|null $name = 'Acme'): SourceSettings
    {
        return new SourceSettings(new Repository(['app' => ['name' => $name], 'audit-log' => ['source' => $source]]));
    }
}
