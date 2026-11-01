<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;

/**
 * Unit tests for the field rule: the path, handling and segments it keeps, the
 * owner an encrypted field must name and no other field may, the owner paths it
 * refuses, and how two rules compare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldRule::class)]
final class FieldRuleTest extends TestCase
{
    /** @var string The message an encrypted field without an owner fails with. */
    private const string MISSING_OWNER_MESSAGE = 'An encrypted field must name its owner: `KeyOwner::ACTOR`, `KeyOwner::SUBJECT` or the path of a property holding a reference.';

    /** @var string The message an owner on a field that is not encrypted fails with. */
    private const string UNEXPECTED_OWNER_MESSAGE = 'Only an encrypted field names an owner.';

    /** @var string The message a path outside the grammar fails with. */
    private const string GRAMMAR_MESSAGE = 'A field path must be dot-separated keys, each non-empty, with `*` alone matching one key or list index.';

    /**
     * Rows of `[handling]`: every handling but `encrypt`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling}>
     */
    public static function provideOwnerlessHandlings(): iterable
    {
        yield from [
            'retain'       => [FieldHandling::RETAIN],
            'redact'       => [FieldHandling::REDACT],
            'pseudonymise' => [FieldHandling::PSEUDONYMISE],
            'drop'         => [FieldHandling::DROP],
        ];
    }

    /**
     * A rule keeps its path as written, its handling, and the path's segments,
     * with no owner.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @return void
     */
    #[DataProvider('provideOwnerlessHandlings')]
    public function testKeepsThePathHandlingAndSegments(FieldHandling $handling): void
    {
        $rule = new FieldRule('card.holder', $handling);

        self::assertSame('card.holder', $rule->path);
        self::assertSame($handling, $rule->handling);
        self::assertSame(['card', 'holder'], $rule->segments);
        self::assertNull($rule->owner);
    }

    /**
     * Rows of `[owner]`: each kind of owner.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner}>
     */
    public static function provideOwnerKinds(): iterable
    {
        yield from [
            'the actor'   => [KeyOwner::ACTOR],
            'the subject' => [KeyOwner::SUBJECT],
        ];
    }

    /**
     * An encrypted field may be owned by the record's actor or its subject.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner  $owner
     * @return void
     */
    #[DataProvider('provideOwnerKinds')]
    public function testAnEncryptedFieldMayBeOwnedByTheActorOrTheSubject(KeyOwner $owner): void
    {
        $rule = new FieldRule('card_holder', FieldHandling::ENCRYPT, $owner);

        self::assertSame(FieldHandling::ENCRYPT, $rule->handling);
        self::assertSame($owner, $rule->owner);
        self::assertSame(['card_holder'], $rule->segments);
    }

    /**
     * An encrypted field may be owned by the property holding a reference,
     * named by its path as written, nested or not.
     *
     * @return void
     */
    public function testAnEncryptedFieldMayBeOwnedByAPropertyHoldingAReference(): void
    {
        self::assertSame('approver', (new FieldRule('approver_email', FieldHandling::ENCRYPT, 'approver'))->owner);
        self::assertSame('card.owner', (new FieldRule('card.holder', FieldHandling::ENCRYPT, 'card.owner'))->owner);
    }

    /**
     * Rows of `[owner]`: no owner, and an empty owner's path.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideMissingOwners(): iterable
    {
        yield from [
            'no owner'    => [null],
            'empty owner' => [''],
        ];
    }

    /**
     * An encrypted field without an owner is refused, since there would be no
     * key to store it under.
     *
     * @param  ?string  $owner
     * @return void
     */
    #[DataProvider('provideMissingOwners')]
    public function testAnEncryptedFieldWithoutAnOwnerIsRefused(?string $owner): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MISSING_OWNER_MESSAGE);

        new FieldRule('card_holder', FieldHandling::ENCRYPT, $owner);
    }

    /**
     * A field that is not encrypted names no owner: an owner kind, a path, and
     * an empty string are each refused.
     *
     * @return void
     */
    public function testOnlyAnEncryptedFieldNamesAnOwner(): void
    {
        $cases = [
            [FieldHandling::REDACT, KeyOwner::ACTOR],
            [FieldHandling::DROP, 'approver'],
            [FieldHandling::RETAIN, ''],
        ];

        foreach ($cases as [$handling, $owner]) {
            try {
                new FieldRule('card_holder', $handling, $owner);

                self::fail(sprintf('Expected an owner on a %s field to be refused.', $handling->value));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::UNEXPECTED_OWNER_MESSAGE, $exception->getMessage());
            }
        }
    }

    /**
     * An owner's path must name one property, so a path with `*` is refused.
     *
     * @return void
     */
    public function testAnOwnerPathWithAWildcardIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An owner\'s path must name one property, without `*`.');

        new FieldRule('items.*.card_holder', FieldHandling::ENCRYPT, 'items.*.owner');
    }

    /**
     * An owner's path follows the field path grammar, and a malformed one is
     * refused with the grammar's own message.
     *
     * @return void
     */
    public function testAMalformedOwnerPathIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GRAMMAR_MESSAGE);

        new FieldRule('card_holder', FieldHandling::ENCRYPT, 'a..b');
    }

    /**
     * An owner's path with a segment beginning `_audit` is refused as any other
     * such path is.
     *
     * @return void
     */
    public function testAReservedOwnerPathIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A field path\'s segments may not begin `_audit`, which is reserved for the package\'s own metadata.');

        new FieldRule('card_holder', FieldHandling::ENCRYPT, '_audit.owner');
    }

    /**
     * An encrypted field cannot be owned by itself, since the reference its key
     * is found through would be the value being encrypted.
     *
     * @return void
     */
    public function testAnEncryptedFieldCannotOwnItself(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An encrypted field cannot be its own owner.');

        new FieldRule('card.holder', FieldHandling::ENCRYPT, 'card.holder');
    }

    /**
     * A malformed path is refused with the grammar's message.
     *
     * @return void
     */
    public function testAMalformedPathIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GRAMMAR_MESSAGE);

        new FieldRule('card..holder', FieldHandling::RETAIN);
    }

    /**
     * The path is checked before the owner, so a malformed path is refused with
     * the grammar's message even when the owner is also missing.
     *
     * @return void
     */
    public function testThePathIsCheckedBeforeTheOwner(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GRAMMAR_MESSAGE);

        new FieldRule('card..holder', FieldHandling::ENCRYPT);
    }

    /**
     * Rows of `[one rule, another, whether they are equal]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\FieldRule, 1: \SineMacula\Laravel\AuditLog\Definitions\FieldRule, 2: bool}>
     */
    public static function provideRulePairs(): iterable
    {
        yield from [
            'the same rule'           => [new FieldRule('a', FieldHandling::RETAIN), new FieldRule('a', FieldHandling::RETAIN), true],
            'the same owned rule'     => [new FieldRule('a', FieldHandling::ENCRYPT, KeyOwner::ACTOR), new FieldRule('a', FieldHandling::ENCRYPT, KeyOwner::ACTOR), true],
            'the same owner path'     => [new FieldRule('a', FieldHandling::ENCRYPT, 'b'), new FieldRule('a', FieldHandling::ENCRYPT, 'b'), true],
            'another path'            => [new FieldRule('a', FieldHandling::RETAIN), new FieldRule('b', FieldHandling::RETAIN), false],
            'another handling'        => [new FieldRule('a', FieldHandling::RETAIN), new FieldRule('a', FieldHandling::DROP), false],
            'another owner kind'      => [new FieldRule('a', FieldHandling::ENCRYPT, KeyOwner::ACTOR), new FieldRule('a', FieldHandling::ENCRYPT, KeyOwner::SUBJECT), false],
            'another owner path'      => [new FieldRule('a', FieldHandling::ENCRYPT, 'b'), new FieldRule('a', FieldHandling::ENCRYPT, 'c'), false],
            'an owner kind or a path' => [new FieldRule('a', FieldHandling::ENCRYPT, KeyOwner::ACTOR), new FieldRule('a', FieldHandling::ENCRYPT, 'actor'), false],
        ];
    }

    /**
     * Two rules are equal only when their path, handling and owner all are, and
     * equality is symmetric.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\FieldRule  $one
     * @param  \SineMacula\Laravel\AuditLog\Definitions\FieldRule  $another
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideRulePairs')]
    public function testEqualsComparesPathHandlingAndOwner(FieldRule $one, FieldRule $another, bool $expected): void
    {
        self::assertSame($expected, $one->equals($another));
        self::assertSame($expected, $another->equals($one));
    }
}
