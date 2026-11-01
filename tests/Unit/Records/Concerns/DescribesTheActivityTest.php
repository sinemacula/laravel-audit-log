<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\Concerns\DescribesTheActivity;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\Normalised;
use Tests\Unit\Stubs\Enums\StubActivity;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\Enums\StubNumberedActivity;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for how a pending record describes its activity: the event code,
 * the subject, actor, principal and tenant, `by(null)` against an actor never
 * given, the credential and correlation ids, normalised properties with the
 * reserved metadata refused at any depth, and the capped note with its owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRecord::class)]
#[CoversTrait(DescribesTheActivity::class)]
final class DescribesTheActivityTest extends TestCase
{
    /** @var string The refusal of a reserved property key. */
    private const string RESERVED = 'Keys beginning `_audit` are reserved for the package\'s own metadata.';

    /** @var string The refusal of a malformed correlation id. */
    private const string CORRELATION = 'A correlation id must be namespaced, as `<namespace>:<value>`, and from 1 to 191 characters with no control characters.';

    /**
     * Clear the morph map after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * A code is taken as a string or as a string-backed enum case.
     *
     * @return void
     */
    public function testEventTakesACodeOrAStringBackedEnum(): void
    {
        self::assertSame('user.suspended', (new PendingRecord)->event('user.suspended')->snapshot()->code?->value);
        self::assertSame('invoice.approved', (new PendingRecord)->event(StubActivity::APPROVED)->snapshot()->code?->value);
    }

    /**
     * An invalid code, or an enum not backed by strings, is refused.
     *
     * @return void
     */
    public function testEventRefusesAnInvalidCode(): void
    {
        try {
            (new PendingRecord)->event(StubNumberedActivity::FIRST);
            self::fail('Expected an integer-backed enum to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An event code enum must be backed by strings.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $message = 'An event code must be lower-case dotted segments, such as `invoice.approved`:'
            . ' each a letter, then letters, digits or underscores, in at least two segments.';

        $this->expectExceptionMessage($message);

        (new PendingRecord)->event('invoice');
    }

    /**
     * A caller's code may not begin with the package's reserved prefix.
     *
     * @return void
     */
    public function testEventRefusesTheReservedPrefix(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The `audit_log.` prefix is reserved for the package\'s own event codes.');

        (new PendingRecord)->event(StubActivity::RESERVED);
    }

    /**
     * The last code given wins.
     *
     * @return void
     */
    public function testTheLastEventCodeWins(): void
    {
        self::assertSame('user.suspended', (new PendingRecord)->event('invoice.approved')->event('user.suspended')->snapshot()->code?->value);
    }

    /**
     * Rows of `[subject, the reference expected]`: a saved model and a
     * reference.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference), 1: \SineMacula\Laravel\AuditLog\Records\Reference}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideSubjects(): iterable
    {
        yield from [
            'a saved model' => [static fn (): Model => (new StubUser)->forceFill(['id' => 42]), Reference::of(StubUser::class, '42')],
            'a reference'   => [static fn (): Reference => Reference::of('invoice', 'inv_0042'), Reference::of('invoice', 'inv_0042')],
        ];
    }

    /**
     * A subject is a model, by its reference, or a reference, kept as given;
     * the last subject given wins.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference)  $subject
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $expected
     * @return void
     */
    #[DataProvider('provideSubjects')]
    public function testOnTakesAModelOrAReference(\Closure $subject, Reference $expected): void
    {
        self::assertEquals($expected, (new PendingRecord)->on($subject())->snapshot()->subject);
        self::assertEquals($expected, (new PendingRecord)->on(Reference::of('other', '1'))->on($subject())->snapshot()->subject);
    }

    /**
     * A model with no key cannot be a subject.
     *
     * @return void
     */
    public function testOnRefusesAnUnsavedModel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A model must have a key before it can be referenced; save it first.');

        (new PendingRecord)->on(new StubUser);
    }

    /**
     * An actor is a model, by its reference under the morph map, or a
     * reference; the last actor given wins.
     *
     * @return void
     */
    public function testByTakesAModelOrAReference(): void
    {
        Relation::morphMap(['user' => StubUser::class]);

        self::assertEquals(Reference::of('user', '7'), (new PendingRecord)->by((new StubUser)->forceFill(['id' => 7]))->snapshot()->actor);
        self::assertEquals(Reference::of('service', 'billing'), (new PendingRecord)->by(Reference::of('service', 'billing'))->snapshot()->actor);
        self::assertEquals(Reference::of('service', 'billing'), (new PendingRecord)->by(Reference::of('user', '7'))->by(Reference::of('service', 'billing'))->snapshot()->actor);
    }

    /**
     * `by(null)` says explicitly that no one did it: the actor is `null`, and a
     * contributor's actor does not fill it.
     *
     * @return void
     */
    public function testByNullIsAnExplicitNoActor(): void
    {
        $pending = (new PendingRecord)->by(null);

        self::assertNull($pending->snapshot()->actor);

        $pending->fillActor(Reference::of('user', '1'));

        self::assertNull($pending->snapshot()->actor);
    }

    /**
     * Without `by()`, the actor is open for a contributor to fill.
     *
     * @return void
     */
    public function testNoByLeavesTheActorOpen(): void
    {
        $pending = new PendingRecord;
        $pending->fillActor(Reference::of('user', '1'));

        self::assertEquals(Reference::of('user', '1'), $pending->snapshot()->actor);
    }

    /**
     * An explicit `by(null)` and an actor never given give different records
     * once a contributor fills the actor: none, and the filled one.
     *
     * @return void
     */
    public function testByNullAndNoByGiveDifferentRecords(): void
    {
        $explicit = (new PendingRecord)->by(null);
        $open     = new PendingRecord;

        $explicit->fillActor(Reference::of('user', '1'));
        $open->fillActor(Reference::of('user', '1'));

        self::assertNull($explicit->snapshot()->actor);
        self::assertEquals(Reference::of('user', '1'), $open->snapshot()->actor);
        self::assertNotEquals($explicit->snapshot(), $open->snapshot());
    }

    /**
     * Rows of `[value, the reference expected]`: a reference, a model and
     * `null`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null), 1: ?\SineMacula\Laravel\AuditLog\Records\Reference}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideOptionalReferences(): iterable
    {
        yield from [
            'a reference' => [static fn (): Reference => Reference::of('team', '7'), Reference::of('team', '7')],
            'a model'     => [static fn (): Model => (new StubUser)->forceFill(['id' => 3]), Reference::of(StubUser::class, '3')],
            'null'        => [static fn (): null => null, null],
        ];
    }

    /**
     * The principal and the tenant each take a reference, a model or `null`,
     * which is an explicit "none" no contributor fills.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null)  $value
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $expected
     * @return void
     */
    #[DataProvider('provideOptionalReferences')]
    public function testAsPrincipalAndForTenantTakeAReferenceAModelOrNull(\Closure $value, ?Reference $expected): void
    {
        $pending = (new PendingRecord)->asPrincipal($value())->forTenant($value());

        $pending->fillPrincipal(Reference::of('filled', '1'));
        $pending->fillTenant(Reference::of('filled', '1'));

        self::assertEquals($expected, $pending->snapshot()->principal);
        self::assertEquals($expected, $pending->snapshot()->tenant);
    }

    /**
     * A credential id is kept exactly; the last one given wins, and an id as
     * long as its column is kept (protects against an off-by-one mutation of
     * the cap).
     *
     * @return void
     */
    public function testUsingCredentialKeepsTheId(): void
    {
        self::assertSame('key_01H', (new PendingRecord)->usingCredential('key_01H')->snapshot()->credentialId);
        self::assertSame('key_02', (new PendingRecord)->usingCredential('key_01')->usingCredential('key_02')->snapshot()->credentialId);
        self::assertSame(str_repeat('é', 191), (new PendingRecord)->usingCredential(str_repeat('é', 191))->snapshot()->credentialId);
    }

    /**
     * Rows of `[credential id]`: ids that are empty, longer than the column or
     * not clean.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedCredentialIds(): iterable
    {
        yield from [
            'empty'               => [''],
            '192 characters'      => [str_repeat('k', 192)],
            'a trailing new line' => ["key\n"],
        ];
    }

    /**
     * Each refused credential id fails, and is never cleaned or cut to fit.
     *
     * @param  string  $credentialId
     * @return void
     */
    #[DataProvider('provideRefusedCredentialIds')]
    public function testUsingCredentialRefusesAnInvalidId(string $credentialId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A credential id must be from 1 to 191 characters, with no control characters.');

        (new PendingRecord)->usingCredential($credentialId);
    }

    /**
     * The credential id parameter is marked sensitive, so it never appears in a
     * stack trace.
     *
     * @return void
     */
    public function testUsingCredentialMarksTheIdSensitive(): void
    {
        $parameter = (new \ReflectionMethod(PendingRecord::class, 'usingCredential'))->getParameters()[0];

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * Rows of `[correlation id]`: namespaced ids, the longest included.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCorrelationIds(): iterable
    {
        yield from [
            'a ticket'                   => ['app:ticket-123'],
            'a value with a colon'       => ['billing:run:42'],
            'the shortest'               => ['a:b'],
            'a value with inner spaces'  => ['app:ticket 123'],
            'a 32-character namespace'   => [str_repeat('n', 32) . ':x'],
            'a hyphen and an underscore' => ['my-app_2:x'],
            '191 characters'             => ['app:' . str_repeat('é', 187)],
        ];
    }

    /**
     * Each namespaced id is kept exactly; the last one given wins.
     *
     * @param  string  $correlationId
     * @return void
     */
    #[DataProvider('provideCorrelationIds')]
    public function testCorrelatedWithKeepsANamespacedId(string $correlationId): void
    {
        self::assertSame($correlationId, (new PendingRecord)->correlatedWith('app:first')->correlatedWith($correlationId)->snapshot()->correlationId);
    }

    /**
     * Rows of `[correlation id]`: ids with no namespace, an empty side, an
     * upper-case namespace, a leading space, too many characters or a control
     * character.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedCorrelationIds(): iterable
    {
        yield from [
            'no namespace'                 => ['ticket-123'],
            'an empty namespace'           => [':x'],
            'an empty value'               => ['app:'],
            'an upper-case namespace'      => ['App:x'],
            'a space after the colon'      => ['app: x'],
            'a namespace starting a digit' => ['1app:x'],
            'a 33-character namespace'     => [str_repeat('n', 33) . ':x'],
            '192 characters'               => ['app:' . str_repeat('é', 188)],
            'a trailing new line'          => ["app:x\n"],
            'a NUL in the value'           => ["app:x\0y"],
            'a bidi override in the value' => ["app:x\u{202E}y"],
            'invalid UTF-8 in the value'   => ["app:x\xC3"],
        ];
    }

    /**
     * Each malformed correlation id is refused, never cleaned or cut.
     *
     * @param  string  $correlationId
     * @return void
     */
    #[DataProvider('provideRefusedCorrelationIds')]
    public function testCorrelatedWithRefusesAnInvalidId(string $correlationId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::CORRELATION);

        (new PendingRecord)->correlatedWith($correlationId);
    }

    /**
     * Properties are normalised when given: a model becomes its reference, an
     * enum its value and a date ISO-8601 UTC.
     *
     * @return void
     */
    public function testWithPropertiesNormalisesTheValues(): void
    {
        $properties = (new PendingRecord)->withProperties([
            'approver' => (new StubUser)->forceFill(['id' => 9, 'password' => 'hunter2']),
            'colour'   => StubColour::RED,
            'due'      => new \DateTimeImmutable('2026-12-01 09:00:00', new \DateTimeZone('Europe/London')),
        ])->snapshot()->properties;

        self::assertSame([
            'approver' => ['type' => StubUser::class, 'id' => '9'],
            'colour'   => 'red',
            'due'      => '2026-12-01T09:00:00.000000Z',
        ], $properties);
    }

    /**
     * Properties merge at the top level, a later key replacing an earlier one
     * in its place and new keys added after.
     *
     * @return void
     */
    public function testWithPropertiesMergesLaterKeysOverEarlier(): void
    {
        $properties = (new PendingRecord)
            ->withProperties(['amount' => '1', 'meta' => ['a' => 1, 'b' => 2]])
            ->withProperties(['meta' => ['c' => 3], 'currency' => 'GBP'])
            ->snapshot()
            ->properties;

        self::assertSame(['amount' => '1', 'meta' => ['c' => 3], 'currency' => 'GBP'], $properties);
    }

    /**
     * A list is not a map of names to values, and is refused.
     *
     * @return void
     */
    public function testWithPropertiesRefusesAList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Properties are a map of names to values, not a list.');

        (new PendingRecord)->withProperties(['a', 'b']);
    }

    /**
     * An empty array adds nothing, and leaves the properties `null` in the
     * snapshot or as they were.
     *
     * @return void
     */
    public function testWithPropertiesOfAnEmptyArrayAddsNothing(): void
    {
        self::assertNull((new PendingRecord)->withProperties([])->snapshot()->properties);
        self::assertSame(['a' => 1], (new PendingRecord)->withProperties(['a' => 1])->withProperties([])->snapshot()->properties);
    }

    /**
     * Rows of `[properties]`: a key beginning `_audit` at the top level, nested
     * in a map, nested in a list, and once its control characters are cleaned.
     *
     * @return iterable<string, array{0: array<string, array<array-key, array<string, int>|int|string>|int>}>
     */
    public static function provideReservedKeys(): iterable
    {
        yield from [
            'the metadata itself'          => [['_audit' => ['note' => 'x']]],
            'a key beginning it'           => [['_auditor' => 1]],
            'nested in a map'              => [['a' => ['_audit' => 1]]],
            'nested in a list'             => [['a' => [['_audit_x' => 1]]]],
            'after a NUL is cleaned'       => [["\0_audit" => 1]],
            'after a bidi override is cut' => [["\u{202E}_audit" => 1]],
        ];
    }

    /**
     * A key beginning `_audit` at any depth is refused, as the normaliser
     * cleans it.
     *
     * @param  array<string, array<array-key, array<string, int>|int|string>|int>  $properties
     * @return void
     */
    #[DataProvider('provideReservedKeys')]
    public function testWithPropertiesRefusesAReservedKeyAtAnyDepth(array $properties): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::RESERVED);

        (new PendingRecord)->withProperties($properties);
    }

    /**
     * A refused call merges nothing: the properties and the collision
     * diagnostics given before it are unchanged.
     *
     * @return void
     */
    public function testARefusedPropertiesCallMergesNothing(): void
    {
        $pending = (new PendingRecord)->withProperties(['amount' => '1', 'b' => 1, "b\0" => 2]);

        try {
            $pending->withProperties(['amount' => '2', 'c' => 1, "c\0" => 2, 'deep' => ['_audit' => 1]]);
            self::fail('Expected the reserved key to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::RESERVED, $exception->getMessage());
        }

        $snapshot = $pending->snapshot();

        self::assertSame(['amount' => '1', 'b' => 1], $snapshot->properties);
        self::assertSame(['b'], $snapshot->collisions);
        self::assertSame(1, $snapshot->collisionCount);
    }

    /**
     * Keys that only contain `audit`, or contain `_audit` after their start,
     * are ordinary keys.
     *
     * @return void
     */
    public function testWithPropertiesAllowsKeysThatOnlyContainAudit(): void
    {
        $properties = ['my_audit' => 1, 'audit' => 2, 'x_audit' => ['audit_log' => 3]];

        self::assertSame($properties, (new PendingRecord)->withProperties($properties)->snapshot()->properties);
    }

    /**
     * Keys that collide once cleaned keep the first value and are diagnosed by
     * their schema path, accumulated across calls and bounded at 32 paths while
     * every collision is counted.
     *
     * @return void
     */
    public function testWithPropertiesCarriesCollisionDiagnostics(): void
    {
        $first = [];

        for ($i = 0; $i < 30; $i++) {
            $first["k{$i}"]   = 1;
            $first["k{$i}\0"] = 2;
        }

        $pending = (new PendingRecord)
            ->withProperties(['a' => 1, "a\0" => 2])
            ->withProperties($first)
            ->withProperties(['items' => [['x' => 1, "x\0" => 2]], 'y' => 1, "y\0" => 2]);

        $snapshot = $pending->snapshot();

        self::assertSame(1, $snapshot->properties['a'] ?? null);
        self::assertCount(Normalised::MAX_COLLISIONS, $snapshot->collisions);
        self::assertSame(33, $snapshot->collisionCount);
        self::assertSame('a', $snapshot->collisions[0]);
        self::assertSame('k0', $snapshot->collisions[1]);
        self::assertSame('items.*.x', $snapshot->collisions[31]);
    }

    /**
     * A note is cleaned of controls and cut at 1,024 bytes without splitting a
     * character.
     *
     * @return void
     */
    public function testWithNoteSanitisesAndCapsTheText(): void
    {
        $long = (new PendingRecord)->withNote(str_repeat('é', 1000))->snapshot()->note;

        self::assertSame("Reviewed  by\u{200B}hand", (new PendingRecord)->withNote("Re\0viewed\r\nby\u{200B}\u{202E}hand")->snapshot()->note);
        self::assertSame(str_repeat('é', 512), $long);
        self::assertSame(PendingRecord::NOTE_MAX_BYTES, strlen($long));
        self::assertTrue(mb_check_encoding($long, 'UTF-8'));
    }

    /**
     * Text that is empty once cleaned is refused.
     *
     * @return void
     */
    public function testWithNoteRefusesEmptyText(): void
    {
        foreach (['', "\0", "\u{202E}"] as $text) {
            try {
                (new PendingRecord)->withNote($text);
                self::fail('Expected an empty note to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A note must have text.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[owner, the owner kept]`: a model, a reference, a key owner and
     * none.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null), 1: \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideNoteOwners(): iterable
    {
        yield from [
            'a model'     => [static fn (): Model => (new StubUser)->forceFill(['id' => 4]), Reference::of(StubUser::class, '4')],
            'a reference' => [static fn (): Reference => Reference::of('user', '4'), Reference::of('user', '4')],
            'the subject' => [static fn (): KeyOwner => KeyOwner::SUBJECT, KeyOwner::SUBJECT],
            'the actor'   => [static fn (): KeyOwner => KeyOwner::ACTOR, KeyOwner::ACTOR],
            'none'        => [static fn (): null => null, null],
        ];
    }

    /**
     * A note keeps its owner, a model as its reference.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null)  $owner
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|\SineMacula\Laravel\AuditLog\Records\Reference|null  $expected
     * @return void
     */
    #[DataProvider('provideNoteOwners')]
    public function testWithNoteKeepsItsOwner(\Closure $owner, KeyOwner|Reference|null $expected): void
    {
        $snapshot = (new PendingRecord)->withNote('Reviewed', $owner())->snapshot();

        self::assertSame('Reviewed', $snapshot->note);
        self::assertEquals($expected, $snapshot->noteOwner);
    }

    /**
     * The last note wins, its text and its owner together: an owned note
     * followed by one without an owner has no owner.
     *
     * @return void
     */
    public function testTheLastNoteWins(): void
    {
        $snapshot = (new PendingRecord)->withNote('First', KeyOwner::SUBJECT)->withNote('Second')->snapshot();

        self::assertSame('Second', $snapshot->note);
        self::assertNull($snapshot->noteOwner);
    }

    /**
     * A model with no key cannot own a note, and a refused note, for its owner
     * or for its text, leaves the earlier note and its owner in place together,
     * so an owned note never loses its owner and becomes plaintext.
     *
     * @return void
     */
    public function testWithNoteRefusesAnUnsavedOwner(): void
    {
        $pending = (new PendingRecord)->withNote('Kept', KeyOwner::SUBJECT);

        $refusals = [
            'A model must have a key before it can be referenced; save it first.' => static fn (): PendingRecord => $pending->withNote('Refused', new StubUser),
            'A note must have text.'                                              => static fn (): PendingRecord => $pending->withNote("\0", null),
        ];

        foreach ($refusals as $message => $refused) {
            try {
                $refused();
                self::fail('Expected the note to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }

            self::assertSame('Kept', $pending->snapshot()->note);
            self::assertSame(KeyOwner::SUBJECT, $pending->snapshot()->noteOwner);
        }
    }

    /**
     * A note never replaces the event code, which a record still needs.
     *
     * @return void
     */
    public function testANoteDoesNotReplaceTheCode(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record needs an event code before it is recorded; set one with `event()`.');

        (new PendingRecord)->withNote('Reviewed')->consume();
    }
}
