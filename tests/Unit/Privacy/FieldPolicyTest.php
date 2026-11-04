<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\OmissionLog;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Privacy\SealingScope;
use SineMacula\Laravel\AuditLog\Privacy\TypedPlaintext;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\MalformedFieldEncrypter;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;

/**
 * Unit tests for the field policy: what each handling does to a value, how the
 * walker selects a rule, what is cut and what never is, whose key a field is
 * sealed under, and what the omission log is told.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldPolicy::class)]
final class FieldPolicyTest extends TestCase
{
    /** @var string The root key every pseudonym here is hashed under. */
    private const string ROOT_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The address a dynamic key or a value could be. */
    private const string DYNAMIC_KEY = 'bob@example.com';

    /** @var string The value that must reach no diagnostic. */
    private const string PLANTED = 's3cr3t';

    /** @var string The id of the entry every value here is sealed for. */
    private const string ENTRY_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var string The id of the log every value here is sealed for. */
    private const string LOG_ID = 'app-eu-1';

    /** @var string A value's shape once pseudonymised: a fingerprint and an HMAC. */
    private const string PSEUDONYM_SHAPE = '/\A[0-9a-f]{16}:[0-9a-f]{64}\z/';

    /** @var \SineMacula\Laravel\AuditLog\Privacy\OmissionLog The log of the call under test. */
    private OmissionLog $omissions;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The reporter of the call under test. */
    private RecordingExceptionHandler $handler;

    /**
     * Give each test its own log and reporter.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->omissions = new OmissionLog;
        $this->handler   = new RecordingExceptionHandler;
    }

    /**
     * The policy is a utility container and cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(FieldPolicy::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(FieldPolicy::class, $instance);
    }

    /**
     * The retained string cap is 1024 bytes.
     *
     * @return void
     */
    public function testTheStringCapIs1024Bytes(): void
    {
        self::assertSame(1024, FieldPolicy::STRING_MAX_BYTES);
    }

    /**
     * Rows of `[value]`: a string, an integer and a map, for each handling.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling, 1: array<string, string>|int|string}>
     */
    public static function provideHandlings(): iterable
    {
        foreach (FieldHandling::cases() as $handling) {
            yield from [
                $handling->value . ', a string'   => [$handling, 'Alice'],
                $handling->value . ', an integer' => [$handling, 42],
                $handling->value . ', a map'      => [$handling, ['name' => 'Alice']],
            ];
        }
    }

    /**
     * Each handling at a literal path gives what its table says, and only a
     * drop reaches the log.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  array<string, string>|int|string  $value
     * @return void
     */
    #[DataProvider('provideHandlings')]
    public function testEachHandlingAtALiteralPath(FieldHandling $handling, array|int|string $value): void
    {
        $owner      = $handling === FieldHandling::ENCRYPT ? KeyOwner::ACTOR : null;
        $definition = EventDefinition::for('a.b')->rule('field', $handling, $owner);

        $result = $this->apply(['field' => $value], $definition, actor: self::actor(), encrypter: new RecordingFieldEncrypter);

        $expected = match ($handling) {
            FieldHandling::RETAIN       => ['field' => $value],
            FieldHandling::REDACT       => ['field' => Redactor::MARKER],
            FieldHandling::PSEUDONYMISE => ['field' => self::hasher()->field($value)],
            FieldHandling::ENCRYPT      => ['field' => ['v' => 1, 'k' => 'key_1', 'c' => base64_encode(CanonicalEncoder::encode($value))]],
            FieldHandling::DROP         => [],
        };

        self::assertSame($expected, $result);
        self::assertSame($handling === FieldHandling::DROP ? ['count' => 1, 'paths' => ['field']] : null, $this->omissions->toArray());
    }

    /**
     * A retain never undoes key redaction: it keeps the marker step one left.
     *
     * @return void
     */
    public function testRetainOnARedactedValueStaysRedacted(): void
    {
        $result = $this->apply(['password' => Redactor::MARKER], EventDefinition::for('a.b')->retain('password'));

        self::assertSame(['password' => Redactor::MARKER], $result);
    }

    /**
     * Rows of `[handling, stored properties]`: what becomes of the marker.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling, 1: array<string, string>}>
     */
    public static function provideHandlingsOfTheMarker(): iterable
    {
        yield from [
            'retain'       => [FieldHandling::RETAIN, ['password' => Redactor::MARKER]],
            'redact'       => [FieldHandling::REDACT, ['password' => Redactor::MARKER]],
            'pseudonymise' => [FieldHandling::PSEUDONYMISE, ['password' => Redactor::MARKER]],
            'encrypt'      => [FieldHandling::ENCRYPT, ['password' => Redactor::MARKER]],
            'drop'         => [FieldHandling::DROP, []],
        ];
    }

    /**
     * The marker stays the marker under every handling and only a drop removes
     * it, because hashing or encrypting it would look like evidence of a value.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  array<string, string>  $expected
     * @return void
     */
    #[DataProvider('provideHandlingsOfTheMarker')]
    public function testAValueStepOneRedactedStaysRedactedUnderEveryHandling(FieldHandling $handling, array $expected): void
    {
        $owner      = $handling === FieldHandling::ENCRYPT ? KeyOwner::ACTOR : null;
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->rule('password', $handling, $owner);

        $result = $this->apply(['password' => Redactor::MARKER], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame($expected, $result);
        self::assertSame([], $encrypter->calls());
    }

    /**
     * An explicit redact reaches a key the matcher exempts, so the exemption is
     * never the last word.
     *
     * @return void
     */
    public function testAnExplicitRedactBeatsAnExemption(): void
    {
        $result = $this->apply(['token_id' => 'tok_1'], EventDefinition::for('a.b')->redact('token_id'));

        self::assertSame(['token_id' => Redactor::MARKER], $result);
    }

    /**
     * A registered code with one rule drops everything else and says so.
     *
     * @return void
     */
    public function testOneRuleDropsEveryOtherField(): void
    {
        $result = $this->apply(['keep' => 1, 'other' => 2, 'more' => 3], EventDefinition::for('a.b')->retain('keep'));

        self::assertSame(['keep' => 1], $result);
        self::assertSame(['count' => 2, 'paths' => ['*']], $this->omissions->toArray());
    }

    /**
     * An unlisted retain keeps the fields no rule names, and logs nothing.
     *
     * @return void
     */
    public function testUnlistedRetainKeepsThem(): void
    {
        $definition = EventDefinition::for('a.b')->redact('card')->unlisted(FieldHandling::RETAIN);

        $result = $this->apply(['card' => '4111', 'other' => ['deep' => 'kept']], $definition);

        self::assertSame(['card' => Redactor::MARKER, 'other' => ['deep' => 'kept']], $result);
        self::assertNull($this->omissions->toArray());
    }

    /**
     * The unlisted default may redact or pseudonymise, and handles a whole
     * container as one value.
     *
     * @return void
     */
    public function testUnlistedRedactAndPseudonymiseApply(): void
    {
        $values = ['name' => 'Alice', 'map' => ['a' => 1]];

        self::assertSame(
            ['name' => Redactor::MARKER, 'map' => Redactor::MARKER],
            $this->apply($values, EventDefinition::for('a.b')->unlisted(FieldHandling::REDACT)),
        );

        self::assertSame(
            ['name' => self::hasher()->field('Alice'), 'map' => self::hasher()->field(['a' => 1])],
            $this->apply($values, EventDefinition::for('a.b')->unlisted(FieldHandling::PSEUDONYMISE)),
        );

        self::assertNull($this->omissions->toArray());
    }

    /**
     * The permissive definition of an unregistered code keeps every field in
     * its order and logs nothing.
     *
     * @return void
     */
    public function testAPermissiveDefinitionKeepsEverythingInOrder(): void
    {
        $values = ['z' => 1, 'a' => ['y' => true, 'b' => null], 'm' => [1, 2, 3], 'empty' => []];

        self::assertSame($values, $this->apply($values, self::permissive()));
        self::assertNull($this->omissions->toArray());
    }

    /**
     * A retain beneath the unlisted drop keeps its field and only its field,
     * though the parent has no rule of its own.
     *
     * @return void
     */
    public function testANestedRetainKeepsItAndDropsTheRestOfItsParent(): void
    {
        $values = ['customer' => ['email' => 'a@example.com', 'name' => 'Alice']];

        $result = $this->apply($values, EventDefinition::for('a.b')->retain('customer.email'));

        self::assertSame(['customer' => ['email' => 'a@example.com']], $result);
        self::assertSame(['count' => 1, 'paths' => ['*.*']], $this->omissions->toArray());
    }

    /**
     * A scalar where a rule expects a container has nothing to walk, so the
     * unlisted default decides it, under the path of the rule beneath it.
     *
     * @return void
     */
    public function testAStructuralAncestorThatIsAScalarIsUnlisted(): void
    {
        $definition = EventDefinition::for('a.b')->retain('customer.email');

        self::assertSame([], $this->apply(['customer' => 'Alice'], $definition));
        self::assertSame(['count' => 1, 'paths' => ['customer']], $this->omissions->toArray());

        self::assertSame(['customer' => 'Alice'], $this->apply(['customer' => 'Alice'], $definition->unlisted(FieldHandling::RETAIN)));
        self::assertSame(['customer' => Redactor::MARKER], $this->apply(['customer' => 'Alice'], $definition->unlisted(FieldHandling::REDACT)));
    }

    /**
     * An empty container holds nothing to descend to, so the unlisted default
     * decides it: only an unlisted retain keeps it.
     *
     * @return void
     */
    public function testAnEmptyContainerAtAStructuralAncestorIsUnlisted(): void
    {
        $definition = EventDefinition::for('a.b')->retain('customer.email');

        self::assertSame([], $this->apply(['customer' => []], $definition));
        self::assertSame(['count' => 1, 'paths' => ['customer']], $this->omissions->toArray());

        self::assertSame(['customer' => []], $this->apply(['customer' => []], $definition->unlisted(FieldHandling::RETAIN)));
        self::assertSame(['customer' => Redactor::MARKER], $this->apply(['customer' => []], $definition->unlisted(FieldHandling::REDACT)));
    }

    /**
     * An ancestor the walker empties is removed and not counted itself, since
     * the children it lost already were.
     *
     * @return void
     */
    public function testAStructuralAncestorLeftEmptyIsRemovedAndNotCounted(): void
    {
        $values = ['customer' => ['address' => ['street' => 'x', 'city' => 'y']]];

        $result = $this->apply($values, EventDefinition::for('a.b')->retain('customer.address.postcode'));

        self::assertSame([], $result);
        self::assertSame(['count' => 2, 'paths' => ['*.*.*']], $this->omissions->toArray());
    }

    /**
     * A wildcard over a list's indexes keeps the field in every element and
     * removes an element left empty, reindexing what is left.
     *
     * @return void
     */
    public function testAWildcardListRuleWalksEveryElement(): void
    {
        $values = ['items' => [['sku' => 'a', 'price' => 1], ['price' => 2], ['sku' => 'b']]];

        $result = $this->apply($values, EventDefinition::for('a.b')->retain('items.*.sku'));

        self::assertSame(['items' => [['sku' => 'a'], ['sku' => 'b']]], $result);
        self::assertSame(['count' => 2, 'paths' => ['*.*.*']], $this->omissions->toArray());
    }

    /**
     * A wildcard over a dynamic key reaches the field under every key, and the
     * dynamic key never reaches the log.
     *
     * @return void
     */
    public function testAWildcardKeyRule(): void
    {
        $values = [self::DYNAMIC_KEY => ['phone' => '123', 'name' => 'Bob'], 'other' => ['phone' => '456']];

        $result = $this->apply($values, EventDefinition::for('a.b')->drop('*.phone')->unlisted(FieldHandling::RETAIN));

        self::assertSame([self::DYNAMIC_KEY => ['name' => 'Bob']], $result);
        self::assertSame(['count' => 2, 'paths' => ['*.phone']], $this->omissions->toArray());
    }

    /**
     * A literal index names one element, and is compared before the list is
     * reindexed.
     *
     * @return void
     */
    public function testALiteralIndexRule(): void
    {
        $result = $this->apply(['items' => ['first', 'second', 'third']], EventDefinition::for('a.b')->retain('items.0'));

        self::assertSame(['items' => ['first']], $result);
        self::assertSame(['count' => 2, 'paths' => ['*.*']], $this->omissions->toArray());

        $later = $this->apply(['items' => ['first', 'second', 'third']], EventDefinition::for('a.b')->retain('items.2'));

        self::assertSame(['items' => ['third']], $later);
    }

    /**
     * A rule whose key PHP turned into an integer still finds its field, and an
     * owner's path that names a list index finds its reference.
     *
     * @return void
     */
    public function testANumericKeyIsMatchedAsItsDecimalString(): void
    {
        $values = [5 => 'kept', 6 => 'dropped', 'people' => [['type' => 'user', 'id' => 8]], 'email' => 'a@example.com'];

        $definition = EventDefinition::for('a.b')->retain('5', 'people')->encrypt('email', 'people.0');
        $encrypter  = new RecordingFieldEncrypter;

        $result = $this->apply($values, $definition, encrypter: $encrypter);

        self::assertSame('kept', $result[5] ?? null);
        self::assertArrayNotHasKey(6, $result);
        self::assertSame('8', ($encrypter->calls()[0][0] ?? null)?->id);
    }

    /**
     * A retain keeps walking, so a more specific rule beneath it still decides
     * its own field and the rest stays retained.
     *
     * @return void
     */
    public function testInheritedRetainLetsADescendantRuleApply(): void
    {
        $values = ['customer' => ['name' => 'Alice', 'ssn' => '123', 'card' => '4111', 'address' => ['city' => 'Leeds']]];

        $definition = EventDefinition::for('a.b')->retain('customer')->drop('customer.ssn')->redact('customer.card');

        $result = $this->apply($values, $definition);

        self::assertSame(['customer' => ['name' => 'Alice', 'card' => Redactor::MARKER, 'address' => ['city' => 'Leeds']]], $result);
        self::assertSame(['count' => 1, 'paths' => ['customer.ssn']], $this->omissions->toArray());
    }

    /**
     * An explicit retain keeps its container though every descendant was
     * dropped, because it was retained rather than passed through.
     *
     * @return void
     */
    public function testRetainingEveryDescendantAwayLeavesARetainedEmptyContainer(): void
    {
        $result = $this->apply(['customer' => ['ssn' => '123']], EventDefinition::for('a.b')->retain('customer')->drop('customer.ssn'));

        self::assertSame(['customer' => []], $result);
        self::assertSame(['count' => 1, 'paths' => ['customer.ssn']], $this->omissions->toArray());
    }

    /**
     * An empty container an explicit rule retains stays, where one that is only
     * an ancestor would take the unlisted default.
     *
     * @return void
     */
    public function testAnEmptyContainerARuleRetainsStays(): void
    {
        self::assertSame(['tags' => []], $this->apply(['tags' => []], EventDefinition::for('a.b')->retain('tags')));
        self::assertNull($this->omissions->toArray());
    }

    /**
     * An ancestor walked under the unlisted retain and left empty is removed,
     * because only an explicit rule retains a container left empty.
     *
     * @return void
     */
    public function testAnUnlistedRetainDoesNotKeepAStructuralAncestorLeftEmpty(): void
    {
        $definition = EventDefinition::for('a.b')->drop('customer.ssn')->unlisted(FieldHandling::RETAIN);

        self::assertSame([], $this->apply(['customer' => ['ssn' => '123']], $definition));
        self::assertSame(['count' => 1, 'paths' => ['customer.ssn']], $this->omissions->toArray());
    }

    /**
     * Rows of `[handling, what the whole subtree becomes]`, each with a map and
     * a list: an explicit terminal rule treats its subtree as one value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling, 1: array<array-key, mixed>}>
     */
    public static function provideTerminalSubtrees(): iterable
    {
        foreach ([FieldHandling::REDACT, FieldHandling::PSEUDONYMISE, FieldHandling::ENCRYPT, FieldHandling::DROP] as $handling) {
            yield from [
                $handling->value . ', a map'  => [$handling, ['a' => ['b' => 1], 'c' => 'x']],
                $handling->value . ', a list' => [$handling, [['b' => 1], 'x']],
            ];
        }
    }

    /**
     * A terminal rule handles a container whole, once, so nothing beneath it is
     * walked and only one branch is counted when it is dropped.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  array<array-key, mixed>  $subtree
     * @return void
     */
    #[DataProvider('provideTerminalSubtrees')]
    public function testAnExplicitTerminalAncestorHandlesTheWholeSubtree(FieldHandling $handling, array $subtree): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->rule('tree', $handling, $handling === FieldHandling::ENCRYPT ? KeyOwner::ACTOR : null);

        $result = $this->apply(['tree' => $subtree], $definition, actor: self::actor(), encrypter: $encrypter);

        $expected = match ($handling) {
            FieldHandling::REDACT       => ['tree' => Redactor::MARKER],
            FieldHandling::PSEUDONYMISE => ['tree' => self::hasher()->field($subtree)],
            FieldHandling::ENCRYPT      => ['tree' => ['v' => 1, 'k' => 'key_1', 'c' => base64_encode(CanonicalEncoder::encode($subtree))]],
            default                     => [],
        };

        self::assertSame($expected, $result);
        self::assertCount($handling === FieldHandling::ENCRYPT ? 1 : 0, $encrypter->calls());
        self::assertSame($handling === FieldHandling::DROP ? ['count' => 1, 'paths' => ['tree']] : null, $this->omissions->toArray());
    }

    /**
     * Removing elements from a list reindexes it, at the top level as well as
     * beneath a key, so it is stored as a list and never as a map.
     *
     * @return void
     */
    public function testRemovingListElementsReindexesTheList(): void
    {
        $nested = $this->apply(['items' => ['a', 'b', 'c', 'd']], EventDefinition::for('a.b')->retain('items')->drop('items.1', 'items.2'));

        self::assertSame(['items' => ['a', 'd']], $nested);

        $top = $this->apply(['a', 'b', 'c'], EventDefinition::for('a.b')->drop('0')->unlisted(FieldHandling::RETAIN));

        self::assertSame(['b', 'c'], $top);
    }

    /**
     * Removing keys from a map keeps the others under their keys, in their
     * order, including numeric keys that do not begin at zero.
     *
     * @return void
     */
    public function testRemovingMapKeysKeepsTheOthersAndTheirOrder(): void
    {
        $definition = EventDefinition::for('a.b')->drop('b', '20')->unlisted(FieldHandling::RETAIN);

        self::assertSame(['z' => 1, 'a' => 3], $this->apply(['z' => 1, 'b' => 2, 'a' => 3], $definition));
        self::assertSame([10 => 'x', 30 => 'z'], $this->apply([10 => 'x', 20 => 'y', 30 => 'z'], $definition));
    }

    /**
     * Beneath a structural ancestor, the unlisted default handles each sibling
     * of the descendant a rule names.
     *
     * @return void
     */
    public function testUnlistedHandlingAppliesBeneathAStructuralAncestor(): void
    {
        $values = ['customer' => ['email' => 'a@example.com', 'name' => 'Alice', 'tags' => ['x']]];

        $result = $this->apply($values, EventDefinition::for('a.b')->retain('customer.email')->unlisted(FieldHandling::REDACT));

        self::assertSame(['customer' => ['email' => 'a@example.com', 'name' => Redactor::MARKER, 'tags' => Redactor::MARKER]], $result);
        self::assertNull($this->omissions->toArray());
    }

    /**
     * A retained string is cut to 1024 bytes without splitting a character.
     *
     * @return void
     */
    public function testARetainedStringIsCutTo1024Bytes(): void
    {
        $result = $this->apply(['ascii' => str_repeat('a', 2000), 'exact' => str_repeat('b', 1024), 'wide' => 'a' . str_repeat('é', 1000)], self::permissive());

        self::assertSame(str_repeat('a', 1024), $result['ascii'] ?? null);
        self::assertSame(str_repeat('b', 1024), $result['exact'] ?? null);
        self::assertSame('a' . str_repeat('é', 511), $result['wide'] ?? null);
    }

    /**
     * The cap applies at every depth, under a rule, an inherited retain and the
     * unlisted retain, and to a list's elements.
     *
     * @return void
     */
    public function testCapsApplyAtEveryDepth(): void
    {
        $long = str_repeat('a', 1500);
        $cut  = str_repeat('a', 1024);

        $result = $this->apply(['a' => ['b' => ['c' => [$long, ['d' => $long]]]], 'e' => $long], EventDefinition::for('a.b')->retain('a')->unlisted(FieldHandling::RETAIN));

        self::assertSame(['a' => ['b' => ['c' => [$cut, ['d' => $cut]]]], 'e' => $cut], $result);
    }

    /**
     * A pseudonym covers the complete value and is not cut itself.
     *
     * @return void
     */
    public function testAPseudonymIsNeverCut(): void
    {
        $long = str_repeat('a', 5000);

        $result = $this->apply(['field' => $long], EventDefinition::for('a.b')->pseudonymise('field'));

        self::assertSame(['field' => self::hasher()->field($long)], $result);
        self::assertMatchesRegularExpression(self::PSEUDONYM_SHAPE, self::hasher()->field($long));
    }

    /**
     * A marker in a retained value is kept whole.
     *
     * @return void
     */
    public function testAMarkerIsNeverCut(): void
    {
        self::assertSame(['field' => Redactor::MARKER], $this->apply(['field' => str_repeat('a', 5000)], EventDefinition::for('a.b')->redact('field')));
    }

    /**
     * An envelope longer than the cap is stored whole: the cap is on what goes
     * in, not what comes out.
     *
     * @return void
     */
    public function testAnEnvelopeIsNeverCut(): void
    {
        $envelope  = ['v' => 1, 'k' => 'key_1', 'c' => str_repeat('c', 5000)];
        $encrypter = new MalformedFieldEncrypter($envelope);

        $result = $this->apply(['field' => 'plain'], EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR), actor: self::actor(), encrypter: $encrypter);

        self::assertSame(['field' => $envelope], $result);
    }

    /**
     * Two long strings that share their first 1500 bytes get different hashes,
     * so the cap never runs before the hash.
     *
     * @return void
     */
    public function testPseudonymiseHashesTheCompleteValue(): void
    {
        $prefix = str_repeat('a', 1500);

        $result = $this->apply(['x' => $prefix . 'x', 'y' => $prefix . 'y'], EventDefinition::for('a.b')->pseudonymise('x', 'y'));

        self::assertNotSame($result['x'] ?? null, $result['y'] ?? null);
        self::assertSame(self::hasher()->field($prefix . 'x'), $result['x'] ?? null);
    }

    /**
     * A string is cut to the cap before the encrypter sees it, its encoding
     * counted, without splitting a character.
     *
     * @return void
     */
    public function testEncryptCutsThePlaintextToTheCapBeforeEncrypting(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR)->encrypt('wide', KeyOwner::ACTOR);

        $this->apply(['field' => str_repeat('a', 2000), 'wide' => 'a' . str_repeat('é', 1000)], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(
            ['"' . str_repeat('a', 1022) . '"', '"a' . str_repeat('é', 510) . '"'],
            array_map(static fn (array $call): string => $call[1], $encrypter->calls()),
        );
    }

    /**
     * A string is cut before the encrypter sees it to the longest prefix whose
     * encoding fits 1024 bytes, quotes and escapes counted, without splitting a
     * character, and the field is kept rather than diagnosed.
     *
     * @return void
     */
    public function testAStringIsCutSoItsEncodingFits(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('quoted', KeyOwner::ACTOR)->encrypt('exact', KeyOwner::ACTOR)->encrypt('over', KeyOwner::ACTOR);
        $values     = ['quoted' => str_repeat('"', 600), 'exact' => str_repeat('b', 1022), 'over' => str_repeat('c', 1023)];

        $result = $this->apply($values, $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(
            ['"' . str_repeat('\"', 511) . '"', '"' . str_repeat('b', 1022) . '"', '"' . str_repeat('c', 1022) . '"'],
            array_map(static fn (array $call): string => $call[1], $encrypter->calls()),
        );
        self::assertSame(['quoted', 'exact', 'over'], array_keys($result));
        self::assertNull($this->omissions->toArray());
    }

    /**
     * Rows of `[list element bytes]`: a list whose typed plaintext, its
     * canonical encoding, is one byte short of the limit, and exactly the
     * limit, the brackets and quotes being the four bytes more than its one
     * string.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideContainersWithinTheCap(): iterable
    {
        yield from [
            'a byte short of the cap' => [1019],
            'exactly the cap'         => [1020],
        ];
    }

    /**
     * A container whose encoding fits the limit reaches the encrypter whole, as
     * its canonical encoding, and nothing is omitted.
     *
     * @param  int  $bytes
     * @return void
     */
    #[DataProvider('provideContainersWithinTheCap')]
    public function testAContainerWithinTheCapIsSealedWhole(int $bytes): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $tree      = [str_repeat('x', $bytes)];

        $result = $this->apply(['tree' => $tree], EventDefinition::for('a.b')->encrypt('tree', KeyOwner::ACTOR), actor: self::actor(), encrypter: $encrypter);

        self::assertArrayHasKey('tree', $result);
        self::assertSame(CanonicalEncoder::encode($tree), $encrypter->calls()[0][1]);
        self::assertSame($bytes + 4, strlen($encrypter->calls()[0][1]));
        self::assertNull($this->omissions->toArray());
    }

    /**
     * Rows of `[value]`: containers whose encoding passes the limit, one by a
     * single byte and one by much more, measured in bytes after encoding, an
     * escaped character costing what its escape does.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideContainersPastTheCap(): iterable
    {
        yield from [
            'a byte past the cap'   => [[str_repeat('x', 1021)]],
            'far past the cap'      => [[str_repeat('x', 2000)]],
            'a map past the cap'    => [['a' => str_repeat('x', 2000), 'b' => 1]],
            'past it only in bytes' => [[str_repeat('é', 511)]],
            'past it once escaped'  => [[str_repeat('"', 511)]],
        ];
    }

    /**
     * A value whose encoding passes the limit is removed and logged under its
     * rule's path, rather than sealed as JSON that could never be decoded, and
     * the encrypter never sees it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $tree
     * @return void
     */
    #[DataProvider('provideContainersPastTheCap')]
    public function testAContainerPastTheCapIsDroppedAndDiagnosed(array $tree): void
    {
        $encrypter = new RecordingFieldEncrypter;

        $definition = EventDefinition::for('a.b')->encrypt('tree', KeyOwner::ACTOR)->retain('kept');

        $result = $this->apply(['tree' => $tree, 'kept' => 'x'], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(['kept' => 'x'], $result);
        self::assertSame([], $encrypter->calls());
        self::assertSame(['count' => 1, 'paths' => ['tree']], $this->omissions->toArray());
    }

    /**
     * A value whose encoding passes the limit only once escaped is removed
     * without reaching the encrypter, while one whose encoding just fits is
     * sealed, so the limit is the encoding's and never the value's.
     *
     * @return void
     */
    public function testAValueWhoseEncodingPassesTheLimitIsDroppedWithoutTheEncrypter(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('over', KeyOwner::ACTOR)->encrypt('fits', KeyOwner::ACTOR);
        $fits       = [str_repeat('\\', 510)];

        $result = $this->apply(['over' => ['a' => str_repeat("\t", 600)], 'fits' => $fits], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(['fits'], array_keys($result));
        self::assertSame([CanonicalEncoder::encode($fits)], array_map(static fn (array $call): string => $call[1], $encrypter->calls()));
        self::assertSame(1024, strlen($encrypter->calls()[0][1]));
        self::assertSame(['count' => 1, 'paths' => ['over']], $this->omissions->toArray());
    }

    /**
     * A container's single value is its canonical encoding, so the order of its
     * keys makes no difference to its pseudonym.
     *
     * @return void
     */
    public function testAContainerIsPseudonymisedAsItsCanonicalEncoding(): void
    {
        $definition = EventDefinition::for('a.b')->pseudonymise('tree');

        $result = $this->apply(['tree' => ['b' => 1, 'a' => 2]], $definition);

        self::assertSame(['tree' => self::hasher()->field(['a' => 2, 'b' => 1])], $result);
    }

    /**
     * A container reaches the encrypter as its canonical encoding, keys sorted.
     *
     * @return void
     */
    public function testAContainerIsEncryptedAsItsCanonicalEncoding(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        $this->apply(['tree' => ['b' => 1, 'a' => 2]], EventDefinition::for('a.b')->encrypt('tree', KeyOwner::ACTOR), actor: self::actor(), encrypter: $encrypter);

        self::assertSame('{"a":2,"b":1}', $encrypter->calls()[0][1] ?? null);
    }

    /**
     * Rows of `[value, plaintext]`: every type is sealed as its canonical
     * encoding, a string as a JSON string with its quotes, so the string
     * `"true"` and the boolean `true` are sealed apart.
     *
     * @return iterable<string, array{0: bool|int|string|null, 1: string}>
     */
    public static function provideScalarPlaintexts(): iterable
    {
        yield from [
            'a string'         => ['Alice', '"Alice"'],
            'an empty string'  => ['', '""'],
            'a string of true' => ['true', '"true"'],
            'a string of null' => ['null', '"null"'],
            'a string of 42'   => ['42', '"42"'],
            'an int'           => [42, '42'],
            'true'             => [true, 'true'],
            'false'            => [false, 'false'],
            'null'             => [null, 'null'],
            'an escape'        => ['a"b\c/é', '"a\"b\\\c/é"'],
        ];
    }

    /**
     * What each value is sealed as: its typed plaintext, which decodes back to
     * the value with its type.
     *
     * @param  bool|int|string|null  $value
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideScalarPlaintexts')]
    public function testThePlaintextIsTyped(bool|int|string|null $value, string $plaintext): void
    {
        $encrypter = new RecordingFieldEncrypter;

        $this->apply(['field' => $value], EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR), actor: self::actor(), encrypter: $encrypter);

        self::assertSame($plaintext, $encrypter->calls()[0][1] ?? null);
        self::assertSame($value, TypedPlaintext::decode($plaintext));
    }

    /**
     * Rows of `[value]`: every value the normaliser leaves but a string, which
     * a retain leaves as it is.
     *
     * @return iterable<string, array{0: bool|int|null}>
     */
    public static function provideRetainedScalars(): iterable
    {
        yield from [
            'an integer' => [42],
            'true'       => [true],
            'false'      => [false],
            'null'       => [null],
        ];
    }

    /**
     * Anything but a string is retained as it is, and a kept `null` is not a
     * removal.
     *
     * @param  bool|int|null  $value
     * @return void
     */
    #[DataProvider('provideRetainedScalars')]
    public function testARetainedScalarIsKeptAsItIs(bool|int|null $value): void
    {
        self::assertSame(['field' => $value], $this->apply(['field' => $value], EventDefinition::for('a.b')->retain('field')));
        self::assertNull($this->omissions->toArray());
    }

    /**
     * Anything but a string hashes as its canonical encoding, a kept `null` and
     * a boolean included, and none of them is a removal.
     *
     * @param  bool|int|null  $value
     * @return void
     */
    #[DataProvider('provideRetainedScalars')]
    public function testAScalarIsPseudonymisedAsItsCanonicalEncoding(bool|int|null $value): void
    {
        $result = $this->apply(['field' => $value], EventDefinition::for('a.b')->pseudonymise('field'));

        self::assertSame(['field' => self::hasher()->field($value)], $result);
        self::assertNull($this->omissions->toArray());
    }

    /**
     * A float never survives normalisation, so one here fails the write, naming
     * only its type, whether hashed or sealed.
     *
     * @return void
     */
    public function testAValueTheNormaliserNeverLeavesFailsTheWrite(): void
    {
        try {
            $this->apply(['field' => 1.5], EventDefinition::for('a.b')->pseudonymise('field'));
            self::fail('Expected the value to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A value of type float cannot be pseudonymised.', $exception->getMessage());
        }

        $this->expectException(\UnexpectedValueException::class);

        $this->apply(['field' => 1.5], EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR), actor: self::actor(), encrypter: new RecordingFieldEncrypter);
    }

    /**
     * Capping cuts every string at every depth, keeps every key and its order,
     * and leaves anything else as it is.
     *
     * @return void
     */
    public function testCappedCutsEveryPlainString(): void
    {
        $long = str_repeat('a', 1500);
        $cut  = str_repeat('a', 1024);

        $values = ['z' => $long, 'n' => 1, 'empty' => [], 'map' => ['b' => $long, 'a' => [$long, null, true]], 7 => 'short'];

        self::assertSame(['z' => $cut, 'n' => 1, 'empty' => [], 'map' => ['b' => $cut, 'a' => [$cut, null, true]], 7 => 'short'], FieldPolicy::capped($values));
    }

    /**
     * An actor-owned field is sealed under the actor, not the subject.
     *
     * @return void
     */
    public function testTheOwnerIsTheActor(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        $this->apply(['field' => 'x'], EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR), self::actor(), self::subject(), $encrypter);

        self::assertSame(self::actor()->id, ($encrypter->calls()[0][0] ?? null)?->id);
    }

    /**
     * A subject-owned field is sealed under the subject, not the actor.
     *
     * @return void
     */
    public function testTheOwnerIsTheSubject(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        $this->apply(['field' => 'x'], EventDefinition::for('a.b')->encrypt('field', KeyOwner::SUBJECT), self::actor(), self::subject(), $encrypter);

        self::assertSame(self::subject()->id, ($encrypter->calls()[0][0] ?? null)?->id);
    }

    /**
     * Rows of `[reference as held]`: either key order, and a string or integer
     * id, which `Reference` keeps as a string.
     *
     * @return iterable<string, array{0: array<string, int|string>}>
     */
    public static function provideReferencesAsHeld(): iterable
    {
        yield from [
            'type first'   => [['type' => 'customer', 'id' => '9']],
            'id first'     => [['id' => '9', 'type' => 'customer']],
            'an int as id' => [['type' => 'customer', 'id' => 9]],
        ];
    }

    /**
     * A property holding a reference owns the field, at any depth of its path.
     *
     * @param  array<string, int|string>  $held
     * @return void
     */
    #[DataProvider('provideReferencesAsHeld')]
    public function testTheOwnerIsAPropertyHoldingAReference(array $held): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->retain('holder')->encrypt('field', 'holder.owner');

        $result = $this->apply(['holder' => ['owner' => $held], 'field' => 'x'], $definition, encrypter: $encrypter);

        self::assertSame(['v' => 1, 'k' => 'key_9', 'c' => base64_encode('"x"')], $result['field'] ?? null);

        $owner = $encrypter->calls()[0][0] ?? null;

        self::assertSame(['customer', '9'], [$owner?->type, $owner?->id]);
    }

    /**
     * An owner is read before any field is handled, so a drop on the owner's
     * own path still lets it own, whichever comes first in the payload.
     *
     * @return void
     */
    public function testAnOwnerPropertyThatIsItselfDroppedStillOwns(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->drop('owner')->encrypt('field', 'owner');
        $owner      = ['type' => 'customer', 'id' => '9'];

        $first  = $this->apply(['owner' => $owner, 'field' => 'x'], $definition, encrypter: $encrypter);
        $second = $this->apply(['field' => 'x', 'owner' => $owner], $definition, encrypter: $encrypter);

        self::assertSame(['field' => ['v' => 1, 'k' => 'key_9', 'c' => base64_encode('"x"')]], $first);
        self::assertSame($first, $second);
    }

    /**
     * Rows of `[owner, properties]`: every way a field can have no owner. A
     * marker in either part counts, since a field is never keyed on a redacted
     * value. The scalar on the way comes first because reading on from it is an
     * error, which protects against a mutation of the path walk that an absent
     * key would only warn about.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string, 1: array<string, mixed>}>
     */
    public static function provideAbsentOwners(): iterable
    {
        $tooLong = str_repeat('a', Reference::MAX_CHARACTERS + 1);

        yield from [
            'a scalar on the way'     => ['holder.owner', ['holder' => 'x']],
            'no actor'                => [KeyOwner::ACTOR, []],
            'no subject'              => [KeyOwner::SUBJECT, []],
            'an absent path'          => ['holder', []],
            'an absent nested path'   => ['holder.owner', ['holder' => ['other' => 1]]],
            'a scalar'                => ['holder', ['holder' => 'x']],
            'a list of two'           => ['holder', ['holder' => ['customer', '9']]],
            'a map with an extra key' => ['holder', ['holder' => ['type' => 'customer', 'id' => '9', 'name' => 'x']]],
            'a map with type alone'   => ['holder', ['holder' => ['type' => 'customer']]],
            'a map with id alone'     => ['holder', ['holder' => ['id' => '9']]],
            'a map of other keys'     => ['holder', ['holder' => ['kind' => 'customer', 'key' => '9']]],
            'a type of no string'     => ['holder', ['holder' => ['type' => 9, 'id' => '9']]],
            'an id of a boolean'      => ['holder', ['holder' => ['type' => 'customer', 'id' => true]]],
            'an id of a map'          => ['holder', ['holder' => ['type' => 'customer', 'id' => ['x']]]],
            'an id Reference refuses' => ['holder', ['holder' => ['type' => 'customer', 'id' => $tooLong]]],
            'an empty id'             => ['holder', ['holder' => ['type' => 'customer', 'id' => '']]],
            'a redacted owner'        => ['holder', ['holder' => Redactor::MARKER]],
            'a redacted type'         => ['holder', ['holder' => ['type' => Redactor::MARKER, 'id' => '9']]],
            'a redacted id'           => ['holder', ['holder' => ['type' => 'customer', 'id' => Redactor::MARKER]]],
        ];
    }

    /**
     * A field with no owner is removed and diagnosed, the encrypter is never
     * called, and no plaintext is stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string  $owner
     * @param  array<string, mixed>  $values
     * @return void
     */
    #[DataProvider('provideAbsentOwners')]
    public function testANoOwnerFieldIsDroppedAndDiagnosed(KeyOwner|string $owner, array $values): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('field', $owner);

        $result = $this->apply([...$values, 'field' => self::PLANTED], $definition, encrypter: $encrypter);

        self::assertArrayNotHasKey('field', $result);
        self::assertSame([], $encrypter->calls());
        self::assertContains('field', $this->omissions->toArray()['paths'] ?? []);
    }

    /**
     * Each rule finds the owner its own path names, not another rule's.
     *
     * @return void
     */
    public function testEachRuleHasItsOwnOwner(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('a', KeyOwner::ACTOR)->encrypt('b', KeyOwner::SUBJECT)->encrypt('c', 'd')->drop('d');
        $values     = ['a' => '1', 'b' => '2', 'c' => '3', 'd' => ['type' => 'x', 'id' => '7']];

        $this->apply($values, $definition, self::actor(), self::subject(), $encrypter);

        self::assertSame(
            [[self::actor()->id, '"1"'], [self::subject()->id, '"2"'], ['7', '"3"']],
            array_map(static fn (array $call): array => [$call[0]->id, $call[1]], $encrypter->calls()),
        );
    }

    /**
     * Every match of a wildcard rule is sealed under the one owner the rule
     * names, and the owner's list is not reindexed under it.
     *
     * @return void
     */
    public function testEveryWildcardMatchUsesTheSameOwner(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->retain('items')->encrypt('items.*.email', 'owner');
        $values     = ['owner' => ['type' => 'customer', 'id' => '9'], 'items' => [['email' => 'a'], ['email' => 'b'], ['email' => 'c']]];

        $result = $this->apply($values, $definition, encrypter: $encrypter);

        self::assertSame(['9', '9', '9'], array_map(static fn (array $call): string => $call[0]->id, $encrypter->calls()));
        self::assertSame(['"a"', '"b"', '"c"'], array_map(static fn (array $call): string => $call[1], $encrypter->calls()));
        self::assertSame(['v' => 1, 'k' => 'key_9', 'c' => base64_encode('"c"')], $result['items'][2]['email'] ?? null);
    }

    /**
     * An encrypted field is sealed for its path in the stored entry, under
     * `properties`, with the scope's entry, log, tenant, category and every
     * owner of the record.
     *
     * @return void
     */
    public function testAnEnvelopeIsSealedWithItsPath(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->retain('card')->encrypt('card.last4', KeyOwner::ACTOR)->encrypt('note', KeyOwner::SUBJECT);

        $this->apply(['card' => ['last4' => '4242', 'brand' => 'visa'], 'note' => 'x'], $definition, self::actor(), self::subject(), $encrypter);

        $context = $encrypter->contexts()[0];

        self::assertSame([['properties', 'card', 'last4'], ['properties', 'note']], $encrypter->paths());
        self::assertSame(self::ENTRY_ID, $context->entryId);
        self::assertSame(self::LOG_ID, $context->logId);
        self::assertSame(['organisation', 'org_01'], [$context->tenant?->type, $context->tenant?->id]);
        self::assertSame('finance', $context->category);
        self::assertSame(['invoice:2', 'user:1'], array_map(static fn (Reference $owner): string => $owner->type . ':' . $owner->id, $context->owners));
    }

    /**
     * An element of a list is sealed at the index it is stored at once the
     * elements removed before it are gone, whether removed by a rule or left
     * empty, so its envelope opens after the list reindexes.
     *
     * @return void
     */
    public function testAnEnvelopeInAListIsBoundToItsStoredIndex(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('items.*.iban', KeyOwner::ACTOR);

        $result = $this->apply(['items' => ['loose', 'other', ['iban' => 'GB00']]], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame([['properties', 'items', 0, 'iban']], $encrypter->paths());
        self::assertSame(['items' => [['iban' => ['v' => 1, 'k' => 'key_1', 'c' => base64_encode('"GB00"')]]]], $result);

        $emptied    = new RecordingFieldEncrypter;
        $structural = EventDefinition::for('a.b')->drop('items.*.secret')->encrypt('items.*.iban', KeyOwner::ACTOR);

        $kept = $this->apply(['items' => [['secret' => 'x'], ['iban' => 'GB01'], ['secret' => 'y'], ['iban' => 'GB02']]], $structural, actor: self::actor(), encrypter: $emptied);

        self::assertSame([['properties', 'items', 0, 'iban'], ['properties', 'items', 1, 'iban']], $emptied->paths());
        self::assertSame(['v' => 1, 'k' => 'key_1', 'c' => base64_encode('"GB02"')], $kept['items'][1]['iban'] ?? null);
    }

    /**
     * A whole element of a list encrypted by a wildcard is sealed at its stored
     * index, the elements a rule removed before it not counted.
     *
     * @return void
     */
    public function testAWholeListElementIsSealedAtItsStoredIndex(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->retain('items')->drop('items.1')->encrypt('items.*', KeyOwner::ACTOR);

        $this->apply(['items' => ['a', 'b', 'c']], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame([['properties', 'items', 0], ['properties', 'items', 1]], $encrypter->paths());
        self::assertSame(['"a"', '"c"'], array_map(static fn (array $call): string => $call[1], $encrypter->calls()));
    }

    /**
     * A member is named by its key as PHP keys it, whatever its container's
     * shape: a list index and a map key PHP holds as an integer from 0 are
     * integer segments, and any other map key, a negative or zero-padded number
     * included, a string. A map key and a list index never name the same place,
     * since one container is never both.
     *
     * @return void
     */
    public function testSegmentsAreTheMembersKeysAsPhpKeysThem(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('7', KeyOwner::ACTOR)->encrypt('people.*.card', KeyOwner::ACTOR)->encrypt('rows.*.card', KeyOwner::ACTOR);
        $values     = ['7' => 'top', 'people' => [5 => ['card' => 'x'], 'bob' => ['card' => 'y'], -1 => ['card' => 'w'], '05' => ['card' => 'v']], 'rows' => [['card' => 'z']]];

        $this->apply($values, $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(
            [
                ['properties', 7],
                ['properties', 'people', 5, 'card'],
                ['properties', 'people', 'bob', 'card'],
                ['properties', 'people', '-1', 'card'],
                ['properties', 'people', '05', 'card'],
                ['properties', 'rows', 0, 'card'],
            ],
            $encrypter->paths(),
        );
    }

    /**
     * A map that loses every key but 0 to n - 1 is stored as a list, and its
     * members were sealed at the integer segments a reader of that list gives
     * them.
     *
     * @return void
     */
    public function testAMapLeftAsAListKeepsTheSegmentsItsReaderGives(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->encrypt('items.0', KeyOwner::ACTOR)->encrypt('items.1', KeyOwner::ACTOR);

        $kept = $this->apply(['items' => [0 => 'a', 'discard' => 'x', 1 => 'b']], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame([['properties', 'items', 0], ['properties', 'items', 1]], $encrypter->paths());
        self::assertTrue(array_is_list($kept['items'] ?? null));
    }

    /**
     * The owners of a definition's encrypted rules are listed each once, in the
     * order their rules are defined; a rule whose owner is absent, and a rule
     * that does not encrypt, name none.
     *
     * @return void
     */
    public function testOwnersOfListsEveryEncryptedRulesOwnerOnce(): void
    {
        $definition = EventDefinition::for('a.b')
            ->encrypt('a', KeyOwner::SUBJECT)
            ->encrypt('b', KeyOwner::ACTOR)
            ->encrypt('c', 'holder')
            ->encrypt('d', 'absent')
            ->encrypt('e', KeyOwner::ACTOR)
            ->retain('holder')
            ->pseudonymise('f');
        $values = ['holder' => ['type' => 'user', 'id' => '1'], 'other' => ['type' => 'customer', 'id' => '9']];

        $owners = FieldPolicy::ownersOf($values, $definition, self::actor(), self::subject());

        $named = static fn (Reference $owner): string => $owner->type . ':' . $owner->id;

        self::assertSame(['invoice:2', 'user:1'], array_map($named, $owners));
        self::assertSame([], FieldPolicy::ownersOf([], $definition, null, null));
        self::assertSame(['customer:9'], array_map($named, FieldPolicy::ownersOf($values, EventDefinition::for('a.b')->encrypt('x', 'other'), null, null)));
    }

    /**
     * The default encrypter holds no key, so an encrypted field is removed and
     * diagnosed, with nothing to report.
     *
     * @return void
     */
    public function testNoEncrypterDropsAndDiagnoses(): void
    {
        $result = $this->apply(['field' => self::PLANTED], EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR), actor: self::actor(), encrypter: new NoFieldEncrypter);

        self::assertSame([], $result);
        self::assertSame(['count' => 1, 'paths' => ['field']], $this->omissions->toArray());
        self::assertSame([], $this->handler->reports());
    }

    /**
     * A custom encrypter's envelope is stored as the field's value, in place.
     *
     * @return void
     */
    public function testACustomEncrypterStoresItsEnvelope(): void
    {
        $encrypter  = new RecordingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->retain('after')->encrypt('field', KeyOwner::ACTOR)->retain('before');

        $result = $this->apply(['before' => 1, 'field' => 'x', 'after' => 2], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(['before' => 1, 'field' => ['v' => 1, 'k' => 'key_1', 'c' => base64_encode('"x"')], 'after' => 2], $result);
        self::assertNull($this->omissions->toArray());
    }

    /**
     * An envelope of the wrong shape is a failure: the field is removed and
     * diagnosed, and the failure reported once.
     *
     * @return void
     */
    public function testAMalformedEnvelopeDropsAndDiagnoses(): void
    {
        $encrypter = new MalformedFieldEncrypter(['v' => 1, 'k' => 'key_1']);

        $result = $this->apply(['field' => self::PLANTED], EventDefinition::for('a.b')->encrypt('field', KeyOwner::ACTOR), actor: self::actor(), encrypter: $encrypter);

        self::assertSame([], $result);
        self::assertSame(['count' => 1, 'paths' => ['field']], $this->omissions->toArray());
        self::assertContainsOnlyInstancesOf(FieldEncryptionFailedException::class, $this->handler->reports());
        self::assertCount(1, $this->handler->reports());
    }

    /**
     * A throwing encrypter costs each of its fields and never the record: every
     * one is diagnosed, it is called once and the failure reported once.
     *
     * @return void
     */
    public function testAThrowingEncrypterDropsAndDiagnoses(): void
    {
        $encrypter  = new ThrowingFieldEncrypter;
        $definition = EventDefinition::for('a.b')->retain('keep')->encrypt('items.*', KeyOwner::ACTOR);

        $result = $this->apply(['keep' => 1, 'items' => [self::PLANTED, self::PLANTED, self::PLANTED]], $definition, actor: self::actor(), encrypter: $encrypter);

        self::assertSame(['keep' => 1], $result);
        self::assertSame(['count' => 3, 'paths' => ['items.*']], $this->omissions->toArray());
        self::assertSame(1, $encrypter->calls());
        self::assertCount(1, $this->handler->reports());
        self::assertStringNotContainsString(self::PLANTED, $this->handler->reports()[0]->getMessage());
    }

    /**
     * An explicit drop is counted under the path its rule names.
     *
     * @return void
     */
    public function testAnExplicitDropIsCountedWithItsRulePath(): void
    {
        $this->apply(['customer' => ['ssn' => '1']], EventDefinition::for('a.b')->retain('customer')->drop('customer.ssn'));

        self::assertSame(['count' => 1, 'paths' => ['customer.ssn']], $this->omissions->toArray());
    }

    /**
     * A field the unlisted default drops is counted as a star, so a key no rule
     * names never reaches the list.
     *
     * @return void
     */
    public function testAnUnlistedDropIsCountedAsAStar(): void
    {
        $this->apply(['anything' => 1], EventDefinition::for('a.b'));

        self::assertSame(['count' => 1, 'paths' => ['*']], $this->omissions->toArray());
    }

    /**
     * A removed container is one branch, however much it held, and each removed
     * sibling is another.
     *
     * @return void
     */
    public function testCountCountsRemovedBranches(): void
    {
        $values = ['tree' => ['a' => 1, 'b' => ['c' => 2, 'd' => 3]], 'other' => ['e' => 4, 'f' => 5], 'third' => 1];

        $this->apply($values, EventDefinition::for('a.b')->drop('tree'));

        self::assertSame(['count' => 3, 'paths' => ['*', 'tree']], $this->omissions->toArray());
    }

    /**
     * A record with no removal leaves the log empty, so it stores no `omitted`.
     *
     * @return void
     */
    public function testNoRemovalLeavesTheLogEmpty(): void
    {
        $this->apply(['a' => 1, 'b' => 'x', 'c' => [1]], EventDefinition::for('a.b')->retain('a')->redact('b')->pseudonymise('c'));

        self::assertNull($this->omissions->toArray());
    }

    /**
     * Neither a dropped value nor a dynamic key reaches the log, nested, by a
     * wildcard or by the unlisted default.
     *
     * @return void
     */
    public function testNoValueOrDynamicKeyReachesTheLog(): void
    {
        $values = [
            self::DYNAMIC_KEY => self::PLANTED,
            'customer'        => [self::DYNAMIC_KEY => self::PLANTED, 'ssn' => self::PLANTED],
            'items'           => [[self::DYNAMIC_KEY => self::PLANTED]],
            'people'          => [self::DYNAMIC_KEY => ['phone' => self::PLANTED]],
        ];

        $definition = EventDefinition::for('a.b')->retain('customer.email', 'items.*.sku')->drop('people.*.phone');

        $this->apply($values, $definition);

        $log = json_encode($this->omissions->toArray(), JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString(self::DYNAMIC_KEY, $log);
        self::assertStringNotContainsString(self::PLANTED, $log);
        self::assertSame(['*', '*.*', '*.*.*', 'people.*.phone'], $this->omissions->toArray()['paths'] ?? []);
    }

    /**
     * No frame of the policy holds a raw value, with arguments kept in traces,
     * so a failure beneath it exposes nothing that it was walking.
     *
     * @return void
     */
    public function testNoFrameOfAFailureHoldsAValue(): void
    {
        $ignored    = ini_set('zend.exception_ignore_args', '0');
        $definition = EventDefinition::for('a.b')->retain('tree')->pseudonymise('tree.deep.field');

        try {
            $this->apply(['tree' => ['deep' => ['planted' => self::PLANTED, 'field' => 1.5]]], $definition);
            self::fail('Expected the value to be refused.');
        } catch (\UnexpectedValueException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === FieldPolicy::class);

            self::assertStringNotContainsString(self::PLANTED, print_r(array_column($frames, 'args'), true));
            self::assertSame(['apply', 'handled', 'hashable', 'pseudonym', 'retained', 'selected', 'walk'], self::namedFunctions($frames));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }
    }

    /**
     * Rows of `[whether the failure is thrown]`: each way the walker fails with
     * a concrete path on its stack, thrown from a hash with a malformed key and
     * reported from a throwing encrypter.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideWalkerFailures(): iterable
    {
        yield from [
            'a malformed key beneath a pseudonym, thrown' => [true],
            'a throwing encrypter, reported'              => [false],
        ];
    }

    /**
     * A dynamic key under a wildcard is on the walker's stack as part of the
     * concrete path whenever a failure is met, and no frame of the failure,
     * thrown or reported, holds it. The search is of the arrays in the
     * package's frames, closure and helpers alike: this test's own frames hold
     * the payload, and a frame's objects reach the reporter and so the test's
     * frames again.
     *
     * @param  bool  $thrown
     * @return void
     */
    #[DataProvider('provideWalkerFailures')]
    public function testNoFrameOfAFailureHoldsADynamicKey(bool $thrown): void
    {
        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            $failure = $thrown ? $this->thrownBeneathADynamicKey() : $this->reportedBeneathADynamicKey();

            $frames = array_filter($failure->getTrace(), static fn (array $frame): bool => str_starts_with($frame['class'] ?? '', 'SineMacula\\'));

            self::assertContains(FieldPolicy::class, array_column($frames, 'class'));
            self::assertStringNotContainsString(self::DYNAMIC_KEY, print_r(array_filter(array_merge(...array_column($frames, 'args')), is_array(...)), true));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }
    }

    /**
     * What a malformed key throws from a pseudonymise rule over a dynamic key.
     *
     * @return \Throwable
     */
    private function thrownBeneathADynamicKey(): \Throwable
    {
        $hasher     = new IdentifierHasher(new RedactionSettings(new Repository(['audit-log' => ['redaction' => ['key' => 'short']]])));
        $sealer     = new EnvelopeSealer(new NoFieldEncrypter, $this->handler);
        $definition = EventDefinition::for('a.b')->pseudonymise('people.*');

        try {
            FieldPolicy::apply(['people' => [self::DYNAMIC_KEY => 'x']], $definition, null, null, $hasher, $sealer, $this->omissions, self::scope());
        } catch (\InvalidArgumentException $exception) {
            return $exception;
        }

        self::fail('Expected the key to be refused.');
    }

    /**
     * What a throwing encrypter leaves reported from a rule over a dynamic key.
     *
     * @return \Throwable
     */
    private function reportedBeneathADynamicKey(): \Throwable
    {
        $definition = EventDefinition::for('a.b')->encrypt('people.*.card', KeyOwner::ACTOR);

        $this->apply(['people' => [self::DYNAMIC_KEY => ['card' => '4111']]], $definition, Reference::of('user', '7'), null, new ThrowingFieldEncrypter);

        return $this->handler->reports()[0];
    }

    /**
     * The result of the policy over the values, under the test's log, reporter
     * and root key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function apply(array $values, EventDefinition $definition, ?Reference $actor = null, ?Reference $subject = null, ?FieldEncrypter $encrypter = null): array
    {
        $sealer = new EnvelopeSealer($encrypter ?? new NoFieldEncrypter, $this->handler);

        return FieldPolicy::apply($values, $definition, $actor, $subject, self::hasher(), $sealer, $this->omissions, self::scope());
    }

    /**
     * The sorted, distinct names of the frames' methods, without closures.
     *
     * @param  array<array-key, array{function: string}>  $frames
     * @return list<string>
     */
    private static function namedFunctions(array $frames): array
    {
        $names = array_unique(array_filter(array_column($frames, 'function'), static fn (string $name): bool => !str_contains($name, '{closure')));

        sort($names);

        return $names;
    }

    /**
     * The scope every value here is sealed in: an entry of an organisation's,
     * encrypting for the actor and the subject.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\SealingScope
     *
     * @throws \InvalidArgumentException
     */
    private static function scope(): SealingScope
    {
        return new SealingScope(self::ENTRY_ID, self::LOG_ID, Reference::of('organisation', 'org_01'), 'finance', [self::actor(), self::subject()]);
    }

    /**
     * The hasher every pseudonym here is computed with.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher
     */
    private static function hasher(): IdentifierHasher
    {
        return new IdentifierHasher(new RedactionSettings(new Repository(['audit-log' => ['redaction' => ['key' => self::ROOT_KEY]]])));
    }

    /**
     * The permissive definition of an unregistered code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    private static function permissive(): EventDefinition
    {
        return EventDefinition::for('a.b')->unlisted(FieldHandling::RETAIN);
    }

    /**
     * The record's actor.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function actor(): Reference
    {
        return Reference::of('user', '1');
    }

    /**
     * The record's subject.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function subject(): Reference
    {
        return Reference::of('invoice', '2');
    }
}
