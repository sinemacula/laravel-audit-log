<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the context an encrypter is given: the parts it keeps, each
 * malformed part it refuses without naming it, and the owners kept each once
 * and sorted bytewise by type and then id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldContext::class)]
final class FieldContextTest extends TestCase
{
    /** @var string An entry id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-00000000000a';

    /** @var string A log id. */
    private const string LOG_ID = 'app-eu-1';

    /** @var string Why an entry id is refused. */
    private const string BAD_ENTRY_ID = 'A field context\'s entry id must be a lower-case UUID.';

    /** @var string Why a path is refused. */
    private const string BAD_PATH = 'A field context\'s path must be a list of `properties`, `context` or `ip`, then map keys and list indexes, each a'
        . ' string or an integer from 0; `ip` stands alone.';

    /** @var string Why a log id is refused. */
    private const string BAD_LOG_ID = 'A field context\'s log id must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string Why a category is refused. */
    private const string BAD_CATEGORY = 'A field context\'s category must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.';

    /**
     * The context keeps each part as given, and an `ip` path standing alone.
     *
     * @return void
     */
    public function testKeepsEachPart(): void
    {
        $tenant  = Reference::of('App\Models\Team', 3);
        $owner   = Reference::of('App\Models\User', 7);
        $context = new FieldContext(self::ENTRY_ID, ['properties', 'items', 0, 'iban'], self::LOG_ID, $tenant, 'billing', [$owner]);

        self::assertSame(self::ENTRY_ID, $context->entryId);
        self::assertSame(['properties', 'items', 0, 'iban'], $context->path);
        self::assertSame(self::LOG_ID, $context->logId);
        self::assertSame($tenant, $context->tenant);
        self::assertSame('billing', $context->category);
        self::assertSame([$owner], $context->owners);
        self::assertSame(['ip'], (new FieldContext(self::ENTRY_ID, ['ip'], self::LOG_ID, null, 'security', []))->path);
        self::assertSame(['context', 'request'], (new FieldContext(self::ENTRY_ID, ['context', 'request'], self::LOG_ID, null, 'security', []))->path);
        self::assertSame(['properties'], (new FieldContext(self::ENTRY_ID, ['properties'], self::LOG_ID, null, 'security', []))->path);
    }

    /**
     * A map key that spells a number stays a string beside a list index, so
     * `"0"` and `0` are different paths.
     *
     * @return void
     */
    public function testAPathKeepsMapKeysApartFromListIndexes(): void
    {
        $context = new FieldContext(self::ENTRY_ID, ['properties', '0', 0, ''], self::LOG_ID, null, 'security', []);

        self::assertSame(['properties', '0', 0, ''], $context->path);
    }

    /**
     * Rows of `[entry id, path, log id, category, owners, the message]`: each
     * part malformed in turn.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: string, 1: array<array-key, bool|float|int|string|null>, 2: string, 3: string, 4: list<\SineMacula\Laravel\AuditLog\Records\Reference|string>, 5: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideMalformedParts(): iterable
    {
        $owner = Reference::of('App\Models\User', 7);

        yield from [
            'an upper-case entry id'   => [strtoupper(self::ENTRY_ID), ['ip'], self::LOG_ID, 'security', [], self::BAD_ENTRY_ID],
            'an entry id with a brace' => ['{' . self::ENTRY_ID . '}', ['ip'], self::LOG_ID, 'security', [], self::BAD_ENTRY_ID],
            'an empty path'            => [self::ENTRY_ID, [], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a path that is a map'     => [self::ENTRY_ID, ['column' => 'properties'], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a path out of order'      => [self::ENTRY_ID, [1 => 'properties', 0 => 'card'], self::LOG_ID, 'security', [], self::BAD_PATH],
            'another column'           => [self::ENTRY_ID, ['note'], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a column in capitals'     => [self::ENTRY_ID, ['Properties'], self::LOG_ID, 'security', [], self::BAD_PATH],
            'an index first'           => [self::ENTRY_ID, [0, 'properties'], self::LOG_ID, 'security', [], self::BAD_PATH],
            'an ip path with a key'    => [self::ENTRY_ID, ['ip', 'v4'], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a negative index'         => [self::ENTRY_ID, ['properties', -1], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a float segment'          => [self::ENTRY_ID, ['properties', 1.5], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a boolean segment'        => [self::ENTRY_ID, ['properties', true], self::LOG_ID, 'security', [], self::BAD_PATH],
            'a null segment'           => [self::ENTRY_ID, ['properties', null], self::LOG_ID, 'security', [], self::BAD_PATH],
            'an empty log id'          => [self::ENTRY_ID, ['ip'], '', 'security', [], self::BAD_LOG_ID],
            'a log id too long'        => [self::ENTRY_ID, ['ip'], str_repeat('a', 65), 'security', [], self::BAD_LOG_ID],
            'a category in capitals'   => [self::ENTRY_ID, ['ip'], self::LOG_ID, 'Security', [], self::BAD_CATEGORY],
            'an empty category'        => [self::ENTRY_ID, ['ip'], self::LOG_ID, '', [], self::BAD_CATEGORY],
            'an owner that is a name'  => [self::ENTRY_ID, ['ip'], self::LOG_ID, 'security', [$owner, 'user:7'], 'A field context\'s owners must each be a reference.'],
        ];
    }

    /**
     * Each malformed part is refused naming the part, never its value.
     *
     * @param  string  $entryId
     * @param  array<array-key, bool|float|int|string|null>  $path
     * @param  string  $logId
     * @param  string  $category
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference|string>  $owners
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedParts')]
    public function testRefusesEachMalformedPart(string $entryId, array $path, string $logId, string $category, array $owners, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // @phpstan-ignore argument.type, argument.type
        new FieldContext($entryId, $path, $logId, null, $category, $owners);
    }

    /**
     * The owners are kept each once, sorted bytewise by type and then by id, so
     * `10` sorts before `9` and a repeated owner is one owner.
     *
     * @return void
     */
    public function testTheOwnersAreDistinctAndSorted(): void
    {
        $team  = Reference::of('App\Models\Team', 2);
        $ten   = Reference::of('App\Models\User', 10);
        $nine  = Reference::of('App\Models\User', 9);
        $upper = Reference::of('App\Models\User', 'B');
        $lower = Reference::of('App\Models\User', 'a');

        $owners  = [$nine, $lower, $team, $ten, Reference::of('App\Models\User', 9), $upper, $team];
        $context = new FieldContext(self::ENTRY_ID, ['ip'], self::LOG_ID, null, 'security', $owners);

        self::assertSame(
            [['App\Models\Team', '2'], ['App\Models\User', '10'], ['App\Models\User', '9'], ['App\Models\User', 'B'], ['App\Models\User', 'a']],
            array_map(static fn (Reference $owner): array => [$owner->type, $owner->id], $context->owners),
        );
        self::assertSame([], (new FieldContext(self::ENTRY_ID, ['ip'], self::LOG_ID, null, 'security', []))->owners);
    }

    /**
     * Two owners whose type and id would join to the same text stay two owners.
     *
     * @return void
     */
    public function testOwnersThatJoinAlikeStayApart(): void
    {
        $context = new FieldContext(self::ENTRY_ID, ['ip'], self::LOG_ID, null, 'security', [Reference::of('a', 'bc'), Reference::of('ab', 'c')]);

        self::assertCount(2, $context->owners);
    }

    /**
     * The path and the owners are marked sensitive, so no frame of a refusal
     * shows a raw key or an owner.
     *
     * @return void
     */
    public function testThePathAndTheOwnersAreMarkedSensitive(): void
    {
        foreach (['path', 'owners'] as $parameter) {
            $reflected = new \ReflectionParameter([FieldContext::class, '__construct'], $parameter);

            self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }
}
