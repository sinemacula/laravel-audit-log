<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\SealingScope;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the scope a record's values are sealed in: the context it
 * gives each path, sharing one entry, log, tenant, category and list of owners,
 * and the parts and paths it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealingScope::class)]
#[CoversClass(FieldContext::class)]
final class SealingScopeTest extends TestCase
{
    /** @var string An entry id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-00000000000a';

    /** @var string A log id. */
    private const string LOG_ID = 'app-eu-1';

    /**
     * A context at a path names the scope's entry, log, tenant and category,
     * every owner of the record each once and sorted, and the path as given.
     *
     * @return void
     */
    public function testAtGivesAContextAtThePath(): void
    {
        $tenant = Reference::of('organisation', 'org_01');
        $alice  = Reference::of('user', 'alice');
        $scope  = new SealingScope(self::ENTRY_ID, self::LOG_ID, $tenant, 'finance', [Reference::of('user', 'bob'), $alice, Reference::of('user', 'bob')]);

        $context = $scope->at(['properties', 'items', 0, 'iban']);

        self::assertSame(self::ENTRY_ID, $context->entryId);
        self::assertSame(['properties', 'items', 0, 'iban'], $context->path);
        self::assertSame(self::LOG_ID, $context->logId);
        self::assertSame($tenant, $context->tenant);
        self::assertSame('finance', $context->category);
        self::assertSame(['user:alice', 'user:bob'], array_map(static fn (Reference $owner): string => $owner->type . ':' . $owner->id, $context->owners));
        self::assertSame($alice, $context->owners[0]);
    }

    /**
     * Each context of a scope differs only in its path, so every value of a
     * record is sealed for the same entry and the same owners.
     *
     * @return void
     */
    public function testEveryContextSharesTheScope(): void
    {
        $owner = Reference::of('user', 'alice');
        $scope = new SealingScope(self::ENTRY_ID, self::LOG_ID, null, 'general', [$owner]);

        $address = $scope->at(['ip']);
        $note    = $scope->at(['properties', '_audit', 'note']);

        self::assertSame(['ip'], $address->path);
        self::assertSame(['properties', '_audit', 'note'], $note->path);
        self::assertNull($address->tenant);
        self::assertSame([$owner], $address->owners);
        self::assertSame([$owner], $note->owners);
        self::assertNotSame($address, $note);
    }

    /**
     * A scope with no owner gives contexts with none, since a record may
     * encrypt nothing.
     *
     * @return void
     */
    public function testAScopeWithNoOwnerGivesContextsWithNone(): void
    {
        self::assertSame([], (new SealingScope(self::ENTRY_ID, self::LOG_ID, null, 'general', []))->at(['properties', 'card'])->owners);
    }

    /**
     * A scope with no log id seals nothing: it takes no owner, and asking it
     * for a context is a programming error.
     *
     * @return void
     */
    public function testAScopeWithoutALogIdSealsNothing(): void
    {
        $scope = new SealingScope(self::ENTRY_ID, null, null, 'general', []);

        try {
            $scope->at(['properties', 'card']);
            self::fail('Expected a scope without a log id to give no context.');
        } catch (\LogicException $exception) {
            self::assertSame('A record with no owner seals nothing, so its scope gives no context.', $exception->getMessage());
        }

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A record with an owner is sealed for the log its entry is signed into.');

        new SealingScope(self::ENTRY_ID, null, null, 'general', [Reference::of('user', 'alice')]);
    }

    /**
     * Rows of `[path]`: paths no context accepts.
     *
     * @return iterable<string, array{0: array<array-key, int|string>}>
     */
    public static function provideRefusedPaths(): iterable
    {
        yield from [
            'an empty path'           => [[]],
            'another column'          => [['metadata', 'card']],
            'an address with a key'   => [['ip', 'card']],
            'a negative index'        => [['properties', 'items', -1]],
            'not a list'              => [[1 => 'properties', 2 => 'card']],
            'a column that is a list' => [[0, 'card']],
        ];
    }

    /**
     * A path no context accepts is refused when a value is sealed at it, naming
     * nothing of the path.
     *
     * @param  array<array-key, int|string>  $path
     * @return void
     */
    #[DataProvider('provideRefusedPaths')]
    public function testRefusesAnEmptyPath(array $path): void
    {
        $scope = new SealingScope(self::ENTRY_ID, self::LOG_ID, null, 'general', []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A field context\'s path must be a list of `properties`, `context` or `ip`, then map keys and list indexes, each a'
            . ' string or an integer from 0; `ip` stands alone.');

        $scope->at($path);
    }

    /**
     * Rows of `[entry id, log id, category, owners, message]`: each malformed
     * part of a scope.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: list<\SineMacula\Laravel\AuditLog\Records\Reference|string>, 4: string}>
     */
    public static function provideMalformedScopes(): iterable
    {
        yield from [
            'an upper-case entry id' => [strtoupper(self::ENTRY_ID), self::LOG_ID, 'general', [], 'A field context\'s entry id must be a lower-case UUID.'],
            'an empty log id'        => [
                self::ENTRY_ID,
                '',
                'general',
                [],
                'A field context\'s log id must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
            ],
            'a malformed category' => [
                self::ENTRY_ID,
                self::LOG_ID,
                'Finance',
                [],
                'A field context\'s category must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.',
            ],
            'an owner that is not a reference' => [self::ENTRY_ID, self::LOG_ID, 'general', ['user:alice'], 'A field context\'s owners must each be a reference.'],
        ];
    }

    /**
     * A malformed part fails the scope as it is built, before any value is
     * sealed in it.
     *
     * @param  string  $entryId
     * @param  string  $logId
     * @param  string  $category
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference|string>  $owners
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedScopes')]
    public function testRefusesAMalformedScopeAsItIsBuilt(string $entryId, string $logId, string $category, array $owners, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new SealingScope($entryId, $logId, null, $category, $owners); // @phpstan-ignore argument.type
    }

    /**
     * The owners and a path are marked sensitive, since an owner is a person
     * and a path can hold a key the application chose.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testTheOwnersAndThePathAreSensitive(): void
    {
        self::assertCount(1, (new \ReflectionParameter([SealingScope::class, '__construct'], 'owners'))->getAttributes(\SensitiveParameter::class));
        self::assertCount(1, (new \ReflectionParameter([SealingScope::class, 'at'], 'path'))->getAttributes(\SensitiveParameter::class));
    }
}
