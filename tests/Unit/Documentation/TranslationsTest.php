<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;

/**
 * A drift guard for the shipped English event titles; the file is data, which
 * PHPUnit cannot cover.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class TranslationsTest extends TestCase
{
    /** @var string The namespace every class of the package is under. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /** @var string The shipped English titles, relative to the repository's root. */
    private const string CODES = '/lang/en/codes.php';

    /** @var string What a title may not hold: a placeholder's colon, or any control character. */
    private const string FORBIDDEN = '/[:\p{Cc}]/u';

    /**
     * The file's keys are exactly the sorted shipped codes.
     *
     * @return void
     */
    public function testEveryShippedCodeHasATitle(): void
    {
        $codes = self::shippedCodes();

        sort($codes, SORT_STRING);

        self::assertSame($codes, array_keys(self::titles()));
    }

    /**
     * Every title is a trimmed non-empty string, no placeholder or control.
     *
     * @return void
     */
    public function testEveryTitleIsAPlainString(): void
    {
        foreach (self::titles() as $code => $title) {
            $code = (string) $code;

            self::assertIsString($title, $code);
            self::assertNotSame('', $title, $code);
            self::assertSame(trim($title), $title, $code);
            self::assertSame(0, preg_match(self::FORBIDDEN, $title), $code);
        }
    }

    /**
     * The file is flat, keyed by the whole code: no value is an array.
     *
     * @return void
     */
    public function testTheFileIsFlat(): void
    {
        $nested = array_keys(array_filter(self::titles(), is_array(...)));

        self::assertSame([], $nested, 'A title is an array.');
    }

    /**
     * The keys are in byte order, so a new code has one place to go.
     *
     * @return void
     */
    public function testTheKeysAreSorted(): void
    {
        $keys   = array_keys(self::titles());
        $sorted = $keys;

        sort($sorted, SORT_STRING);

        self::assertSame($sorted, $keys);
    }

    /**
     * The walk finds both defining enums, so the checks are not empty.
     *
     * @return void
     */
    public function testTheWalkFindsBothDefiningEnums(): void
    {
        self::assertSame([CapturedActivity::class, PackageActivity::class], self::definingEnums());
        self::assertContains('audit_log.trail_read', self::shippedCodes());
        self::assertContains('authentication.signed_in', self::shippedCodes());
    }

    /**
     * Every code an enum defining events in `src/` ships.
     *
     * @return list<string>
     */
    private static function shippedCodes(): array
    {
        $codes = [];

        foreach (self::definingEnums() as $enum) {
            foreach ($enum::cases() as $case) {
                $codes[] = (string) $case->value;
            }
        }

        return $codes;
    }

    /**
     * The enums in `src/` that define events, sorted by name.
     *
     * @return list<class-string<\SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents>>
     */
    private static function definingEnums(): array
    {
        $root    = dirname(__DIR__, 3) . '/src/';
        $classes = [];
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $class = self::PACKAGE_NAMESPACE . str_replace('/', '\\', substr($file->getPathname(), strlen($root), -4));

            if (!enum_exists($class) || !is_subclass_of($class, DefinesAuditEvents::class)) {
                continue;
            }

            $classes[] = $class;
        }

        sort($classes);

        return $classes;
    }

    /**
     * The shipped titles, by code, as the file returns them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     */
    private static function titles(): array
    {
        $titles = require dirname(__DIR__, 3) . self::CODES;

        self::assertIsArray($titles);

        return $titles;
    }
}
