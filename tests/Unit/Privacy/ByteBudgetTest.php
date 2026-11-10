<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\ByteBudget;
use SineMacula\Laravel\AuditLog\Privacy\OmissionLog;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;

/**
 * Unit tests for the byte budget: the order keys are omitted in, what is never
 * omitted, the masked paths it reports, that the final encoding fits whatever
 * the metadata adds, and that the result depends only on the input's contents.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ByteBudget::class)]
final class ByteBudgetTest extends TestCase
{
    /** @var int The least budget the settings accept for the properties. */
    private const int MINIMUM = 8192;

    /** @var int What the properties' keys may cost at the minimum, beside the reserve. */
    private const int MINIMUM_LIMIT = 3592;

    /** @var int The least budget the settings accept for the context. */
    private const int CONTEXT_MINIMUM = 1024;

    /** @var array{artifact_id: string, kind: string, digest: string, count: int} The largest manifest descriptor: a UUID, the longest kind, a SHA-256 and the greatest member cap the settings allow. */
    private const array LARGEST_MANIFEST = [
        'artifact_id' => 'ffffffff-ffff-7fff-bfff-ffffffffffff',
        'kind'        => 'disclosure',
        'digest'      => 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        'count'       => 1000000,
    ];

    /** @var string An identifier hash as the hasher writes it. */
    private const string HASH = 'aaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /**
     * The budget is a utility container and cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ByteBudget::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ByteBudget::class, $instance);
    }

    /**
     * A payload within its budget comes back as it was, in its order, and
     * nothing is logged.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAPayloadWithinBudgetIsUntouched(): void
    {
        $log = new OmissionLog;

        self::assertSame(['b' => 1, 'a' => ['x' => 'y']], ByteBudget::properties(['b' => 1, 'a' => ['x' => 'y']], null, null, self::definition(), self::MINIMUM, $log));
        self::assertSame(['b' => 1, 'a' => ['x' => 'y']], ByteBudget::context(['b' => 1, 'a' => ['x' => 'y']], self::CONTEXT_MINIMUM, $log));
        self::assertNull($log->toArray());
    }

    /**
     * The metadata sits under `_audit` after the caller's keys, holding the
     * note, the identifier hash and what was omitted, in that order.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testMetadataComesLastInItsFixedOrder(): void
    {
        $log = new OmissionLog;

        $log->add('$ip');

        $result = ByteBudget::properties(['b' => 1, 'a' => 2], 'Checked by hand', self::HASH, self::definition(), self::MINIMUM, $log);

        self::assertSame([
            'b'      => 1,
            'a'      => 2,
            '_audit' => [
                'note'            => 'Checked by hand',
                'identifier_hash' => self::HASH,
                'omitted'         => ['count' => 1, 'paths' => ['$ip']],
            ],
        ], $result);
    }

    /**
     * Rows of `[note, identifier hash, the expected metadata]`: only the parts
     * present appear, and an envelope is kept as the note.
     *
     * @return iterable<string, array{0: array{v: int, k: string, c: string}|string|null, 1: ?string, 2: array<string, array{v: int, k: string, c: string}|string>}>
     */
    public static function provideMetadataParts(): iterable
    {
        yield from [
            'a note alone'    => ['Checked', null, ['note' => 'Checked']],
            'an envelope'     => [['v' => 1, 'k' => 'key', 'c' => 'text'], null, ['note' => ['v' => 1, 'k' => 'key', 'c' => 'text']]],
            'a hash alone'    => [null, self::HASH, ['identifier_hash' => self::HASH]],
            'a note and hash' => ['Checked', self::HASH, ['note' => 'Checked', 'identifier_hash' => self::HASH]],
        ];
    }

    /**
     * The metadata holds only what is present, with nothing else beside it.
     *
     * @param  array{v: int, k: string, c: string}|string|null  $note
     * @param  ?string  $hash
     * @param  array<string, array{v: int, k: string, c: string}|string>  $expected
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideMetadataParts')]
    public function testOnlyThePartsPresentAreWritten(array|string|null $note, ?string $hash, array $expected): void
    {
        self::assertSame(['_audit' => $expected], ByteBudget::properties([], $note, $hash, self::definition(), self::MINIMUM, new OmissionLog));
    }

    /**
     * Nothing to store is `null` in both budgets, not an empty map, and so is a
     * payload with every key omitted from a context.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNothingGivesNull(): void
    {
        $log = new OmissionLog;

        self::assertNull(ByteBudget::properties([], null, null, self::definition(), self::MINIMUM, $log));
        self::assertNull(ByteBudget::context([], self::CONTEXT_MINIMUM, $log));
        self::assertNull($log->toArray());

        self::assertNull(ByteBudget::context(['a' => str_repeat('x', 2000)], self::CONTEXT_MINIMUM, $log));
        self::assertSame(['count' => 1, 'paths' => ['context.*']], $log->toArray());
    }

    /**
     * The largest key goes first, and only as many go as it takes: the smaller
     * ones survive once what remains fits.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheLargestKeyGoesFirst(): void
    {
        $log    = new OmissionLog;
        $values = ['small' => self::costing('small', 1000), 'large' => self::costing('large', 6000), 'medium' => self::costing('medium', 2000)];

        $result = ByteBudget::properties($values, null, null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['small', 'medium', '_audit'], array_keys($result ?? []));
        self::assertSame(['count' => 1, 'paths' => ['*']], $log->toArray());

        $log    = new OmissionLog;
        $values = ['small' => self::costing('small', 1000), 'large' => self::costing('large', 6000), 'medium' => self::costing('medium', 3000)];

        $result = ByteBudget::properties($values, null, null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['small', '_audit'], array_keys($result ?? []));
        self::assertSame(2, $log->toArray()['count'] ?? null);
    }

    /**
     * Keys of equal cost go in the byte order of the key, so `Z` goes before
     * `a`, and only `c` is left here: protects against a case-insensitive or a
     * reversed comparison, each of which leaves another key.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testATieBreaksBytewiseOnTheKey(): void
    {
        $values = ['b' => self::costing('b', 3000), 'c' => self::costing('c', 3000), 'a' => self::costing('a', 3000), 'Z' => self::costing('Z', 3000)];

        $result = ByteBudget::properties($values, null, null, self::definition(), self::MINIMUM, new OmissionLog);

        self::assertSame(['c', '_audit'], array_keys($result ?? []));
    }

    /**
     * A key no rule names goes before one a rule governs, even when it is the
     * smaller: `free_small` goes while the larger `ruled` stays.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testKeysNoRuleNamesGoBeforeRuleGovernedKeys(): void
    {
        $values = ['free_large' => self::costing('free_large', 5000), 'free_small' => self::costing('free_small', 200), 'ruled' => self::costing('ruled', 3500)];

        $result = ByteBudget::properties($values, null, null, self::definition()->retain('ruled'), self::MINIMUM, new OmissionLog);

        self::assertSame(['ruled', '_audit'], array_keys($result ?? []));
    }

    /**
     * A branch holding a rule-governed field goes with the rule-governed keys,
     * even though no rule decides the branch itself, so a retained field is not
     * lost to a smaller key's benefit.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testABranchHoldingARuleGovernedFieldGoesLast(): void
    {
        $values = ['free_large' => self::costing('free_large', 5000), 'free_small' => self::costing('free_small', 200), 'customer' => ['email' => str_repeat('x', 3400)]];

        $result = ByteBudget::properties($values, null, null, self::definition()->retain('customer.email'), self::MINIMUM, new OmissionLog);

        self::assertSame(['customer', '_audit'], array_keys($result ?? []));
    }

    /**
     * Among rule-governed keys the largest still goes first, whatever the rule
     * says of them.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testRuleGovernedKeysGoLargestFirst(): void
    {
        $definition = self::definition()->retain('smaller')->retain('larger.field');
        $values     = ['smaller' => self::costing('smaller', 3000), 'larger' => ['field' => str_repeat('x', 6000)]];

        $result = ByteBudget::properties($values, null, null, $definition, self::MINIMUM, new OmissionLog);

        self::assertSame(['smaller', '_audit'], array_keys($result ?? []));
    }

    /**
     * The note outlasts every other key, even one that is smaller than it, and
     * it goes only when nothing else is left and it still does not fit.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheNoteGoesLastAmongOmittableValues(): void
    {
        $log    = new OmissionLog;
        $note   = self::costing('note', 3000);
        $values = ['free' => self::costing('free', 5000), 'ruled' => self::costing('ruled', 1000)];

        $result = ByteBudget::properties($values, $note, null, self::definition()->retain('ruled'), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['note' => $note, 'omitted' => ['count' => 2, 'paths' => ['*', 'ruled']]]], $result);

        $log    = new OmissionLog;
        $values = ['free' => self::costing('free', 4000)];

        $result = ByteBudget::properties($values, self::costing('note', 5000), null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['omitted' => ['count' => 2, 'paths' => ['*', '_audit.note']]]], $result);
    }

    /**
     * An envelope is costed as it is encoded, so a large one goes like a large
     * plaintext note, and a small one stays.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnEnvelopeIsCostedAsItIsEncoded(): void
    {
        $log = new OmissionLog;

        $result = ByteBudget::properties([], ['v' => 1, 'k' => 'key', 'c' => str_repeat('c', self::MINIMUM)], null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['_audit.note']]]], $result);

        $envelope = ['v' => 1, 'k' => 'key', 'c' => 'text'];

        $result = ByteBudget::properties(['big' => str_repeat('x', self::MINIMUM)], $envelope, null, self::definition(), self::MINIMUM, new OmissionLog);

        self::assertSame($envelope, $result['_audit']['note'] ?? null);
    }

    /**
     * Whatever else goes, the identifier hash and the omitted list stay, and
     * they are not themselves costed as candidates.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheIdentifierHashAndOmittedAreNeverOmitted(): void
    {
        $log = new OmissionLog;

        $log->add('$ip');

        $result = ByteBudget::properties(['huge' => str_repeat('x', self::MINIMUM * 2)], null, self::HASH, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['identifier_hash' => self::HASH, 'omitted' => ['count' => 2, 'paths' => ['$ip', '*']]]], $result);
    }

    /**
     * A large nested value is removed whole: no fragment of it is kept and no
     * path beneath it is reported.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testOmissionStaysAtTheTopLevel(): void
    {
        $log    = new OmissionLog;
        $values = ['nested' => ['keep' => 'small', 'big' => str_repeat('x', self::MINIMUM)], 'other' => 1];

        $result = ByteBudget::properties($values, null, null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['other' => 1, '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $result);
        self::assertStringNotContainsString('small', self::encoded($result));
    }

    /**
     * An omitted key no rule names is reported as `*`, so a dynamic key never
     * reaches the stored list.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnOmittedKeyIsMasked(): void
    {
        $log = new OmissionLog;

        $result = ByteBudget::properties(['bob@example.com' => str_repeat('x', self::MINIMUM)], null, null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $result);
        self::assertStringNotContainsString('bob', self::encoded($result));
    }

    /**
     * An omitted key a rule names, or holding what a rule names, is reported by
     * its name, because the definition already declares it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnOmittedRuleNamedKeyIsLiteral(): void
    {
        $log        = new OmissionLog;
        $definition = self::definition()->retain('invoice')->retain('customer.email');
        $values     = ['invoice' => str_repeat('x', self::MINIMUM), 'customer' => ['email' => str_repeat('x', self::MINIMUM)]];

        ByteBudget::properties($values, null, null, $definition, self::MINIMUM, $log);

        self::assertSame(['count' => 2, 'paths' => ['customer', 'invoice']], $log->toArray());
    }

    /**
     * An omitted note is reported under its fixed path, which no rule and no
     * caller key can begin.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnOmittedNoteIsItsFixedPath(): void
    {
        $log = new OmissionLog;

        $result = ByteBudget::properties([], str_repeat('n', self::MINIMUM), null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['_audit.note']]]], $result);
    }

    /**
     * A caller's key that merely reads like the note's path is an ordinary key:
     * omitting it leaves the note, because the note is never among the keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAKeyNamedLikeTheNotePathIsNotTheNote(): void
    {
        $log = new OmissionLog;

        $result = ByteBudget::properties(['_audit.note' => str_repeat('x', self::MINIMUM)], 'Checked', null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['note' => 'Checked', 'omitted' => ['count' => 1, 'paths' => ['*']]]], $result);
    }

    /**
     * Keys stop going the moment what remains fits beside the reserve: at
     * exactly the limit the next key stays, and one byte over it goes too,
     * which pins each key's cost to the byte.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testOmissionStopsAsSoonAsTheRestFits(): void
    {
        $fits = ['big' => self::costing('big', 6000), 'keep' => self::costing('keep', self::MINIMUM_LIMIT)];

        self::assertSame(['keep', '_audit'], array_keys(ByteBudget::properties($fits, null, null, self::definition(), self::MINIMUM, new OmissionLog) ?? []));

        $over = ['big' => self::costing('big', 6000), 'keep' => self::costing('keep', self::MINIMUM_LIMIT + 1)];

        self::assertSame(['_audit'], array_keys(ByteBudget::properties($over, null, null, self::definition(), self::MINIMUM, new OmissionLog) ?? []));
    }

    /**
     * The note's cost counts toward what remains, its key and punctuation
     * included: at exactly the limit it stays, and one byte over it goes.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheNoteIsCostedToTheByte(): void
    {
        $fitting = self::costing('note', self::MINIMUM_LIMIT);

        $result = ByteBudget::properties(['big' => self::costing('big', 6000)], $fitting, null, self::definition(), self::MINIMUM, new OmissionLog);

        self::assertSame($fitting, $result['_audit']['note'] ?? null);

        $over = self::costing('note', self::MINIMUM_LIMIT + 1);

        $result = ByteBudget::properties(['big' => self::costing('big', 6000)], $over, null, self::definition(), self::MINIMUM, new OmissionLog);

        self::assertArrayNotHasKey('note', self::auditOf($result));
    }

    /**
     * Rows of `[values, note, identifier hash, budget]`: a payload exactly at
     * the limit, one byte over, many small keys, one huge key, and the least
     * budget with metadata beside the keys.
     *
     * @return iterable<string, array{0: array<string, string>, 1: ?string, 2: ?string, 3: int}>
     */
    public static function provideBudgets(): iterable
    {
        $many = [];

        for ($index = 0; $index < 5000; $index++) {
            $many["key_{$index}"] = 'value';
        }

        yield from [
            'exactly at the limit' => [['a' => str_repeat('x', self::MINIMUM - 8)], null, null, self::MINIMUM],
            'one byte over'        => [['a' => str_repeat('x', self::MINIMUM - 7)], null, null, self::MINIMUM],
            'one byte over, split' => [['a' => str_repeat('x', 6000), 'b' => str_repeat('x', self::MINIMUM - 6014)], null, null, self::MINIMUM],
            'many small'           => [$many, null, self::HASH, self::MINIMUM],
            'one huge'             => [['a' => str_repeat('x', 2097152), 'b' => 'small'], 'Checked', self::HASH, 16384],
            'the least budget'     => [['a' => str_repeat('x', 5000), 'b' => str_repeat('y', 3000), 'c' => str_repeat('"', 900)], 'Checked', self::HASH, self::MINIMUM],
        ];
    }

    /**
     * The final encoding is at most the budget, and the log counts every key
     * that went.
     *
     * @param  array<string, string>  $values
     * @param  ?string  $note
     * @param  ?string  $hash
     * @param  int  $budget
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideBudgets')]
    public function testTheFinalEncodingFitsTheBudget(array $values, ?string $note, ?string $hash, int $budget): void
    {
        $log = new OmissionLog;

        $result = ByteBudget::properties($values, $note, $hash, self::definition(), $budget, $log);

        self::assertLessThanOrEqual($budget, strlen(self::encoded($result)));
        self::assertSame(count(array_diff_key($values, $result ?? [])), $log->toArray()['count'] ?? 0);
    }

    /**
     * A payload whose final encoding is exactly the budget is left alone, and
     * one byte more is not: the first comparison is against the budget itself,
     * with the metadata counted.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheBudgetIncludesTheMetadataAtTheLimit(): void
    {
        $bare   = strlen(self::encoded(['a' => '', '_audit' => ['identifier_hash' => self::HASH]]));
        $fits   = ['a' => str_repeat('x', self::MINIMUM - $bare)];
        $result = ByteBudget::properties($fits, null, self::HASH, self::definition(), self::MINIMUM, new OmissionLog);

        self::assertSame(['a' => $fits['a'], '_audit' => ['identifier_hash' => self::HASH]], $result);
        self::assertSame(self::MINIMUM, strlen(self::encoded($result)));

        $log    = new OmissionLog;
        $result = ByteBudget::properties(['a' => $fits['a'] . 'x'], null, self::HASH, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['identifier_hash' => self::HASH, 'omitted' => ['count' => 1, 'paths' => ['*']]]], $result);
    }

    /**
     * The reserve holds the largest metadata there can be, measured rather than
     * assumed: a full hash, the largest manifest descriptor and 32 paths of 128
     * bytes under the largest count, with a comma, which is 4535 bytes.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheReserveHoldsTheLargestMetadata(): void
    {
        $paths = array_map(static fn (int $index): string => str_pad((string) $index, OmissionLog::MAX_PATH_BYTES, 'k'), range(1, OmissionLog::MAX_PATHS));

        $metadata = ['_audit' => ['identifier_hash' => self::HASH, 'manifest' => self::LARGEST_MANIFEST, 'omitted' => ['count' => PHP_INT_MAX, 'paths' => $paths]]];

        self::assertSame(4535, strlen(self::encoded($metadata)) + 1);
        self::assertSame(4600, ByteBudget::METADATA_RESERVE_BYTES);
        self::assertLessThanOrEqual(ByteBudget::METADATA_RESERVE_BYTES, strlen(self::encoded($metadata)) + 1);
    }

    /**
     * The largest manifest descriptor, measured: its key, a lower-case UUID,
     * the longest kind, `disclosure`, a hex SHA-256 and the greatest count the
     * settings allow cost 178 bytes with a comma, which the reserve holds
     * beside the rest of the largest metadata, and still holds should a count
     * reach the largest integer.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheReserveHoldsTheLargestManifest(): void
    {
        $paths = array_map(static fn (int $index): string => str_pad((string) $index, OmissionLog::MAX_PATH_BYTES, 'k'), range(1, OmissionLog::MAX_PATHS));
        $rest  = ['identifier_hash' => self::HASH, 'omitted' => ['count' => PHP_INT_MAX, 'paths' => $paths]];

        $without = strlen(self::encoded(['_audit' => $rest]));
        $with    = strlen(self::encoded(['_audit' => ['identifier_hash' => self::HASH, 'manifest' => self::LARGEST_MANIFEST] + $rest]));

        self::assertSame(178, $with - $without);
        self::assertSame(
            max(array_map(static fn (ArtifactKind $kind): int => strlen($kind->value), ArtifactKind::cases())),
            strlen(self::LARGEST_MANIFEST['kind']),
        );

        $endless = strlen(self::encoded(['_audit' => ['identifier_hash' => self::HASH, 'manifest' => ['count' => PHP_INT_MAX] + self::LARGEST_MANIFEST] + $rest]));

        self::assertLessThan(ByteBudget::METADATA_RESERVE_BYTES, $endless + 1);
    }

    /**
     * The manifest descriptor sits after the identifier hash and before what
     * was omitted, with the note first, and is written as given.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheManifestSitsAfterTheIdentifierHash(): void
    {
        $log = new OmissionLog;

        $log->add('$ip');

        $result = ByteBudget::properties(['b' => 1], 'Checked', self::HASH, self::definition(), self::MINIMUM, $log, self::LARGEST_MANIFEST);

        self::assertSame(['b' => 1, '_audit' => [
            'note'            => 'Checked',
            'identifier_hash' => self::HASH,
            'manifest'        => self::LARGEST_MANIFEST,
            'omitted'         => ['count' => 1, 'paths' => ['$ip']],
        ]], $result);
        $alone = ByteBudget::properties([], null, null, self::definition(), self::MINIMUM, new OmissionLog, self::LARGEST_MANIFEST);

        self::assertSame(['_audit' => ['manifest' => self::LARGEST_MANIFEST]], $alone);
    }

    /**
     * Whatever else goes, the manifest descriptor stays, beside the hash and
     * the omitted list, and it is never itself a candidate: nothing it costs is
     * reported, and the final encoding fits.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheManifestIsNeverOmitted(): void
    {
        $log = new OmissionLog;

        $values = ['huge' => str_repeat('x', self::MINIMUM * 2), 'small' => 1];
        $result = ByteBudget::properties($values, null, self::HASH, self::definition(), self::MINIMUM, $log, self::LARGEST_MANIFEST);

        self::assertSame(['small' => 1, '_audit' => [
            'identifier_hash' => self::HASH,
            'manifest'        => self::LARGEST_MANIFEST,
            'omitted'         => ['count' => 1, 'paths' => ['*']],
        ]], $result);
        self::assertLessThanOrEqual(self::MINIMUM, strlen(self::encoded($result)));
    }

    /**
     * The manifest descriptor is counted in the first comparison too: a payload
     * that fits only without it loses a key with it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheManifestCountsTowardTheBudget(): void
    {
        $bare = strlen(self::encoded(['a' => '']));
        $fits = ['a' => str_repeat('x', self::MINIMUM - $bare)];

        self::assertSame($fits, ByteBudget::properties($fits, null, null, self::definition(), self::MINIMUM, new OmissionLog));

        $result = ByteBudget::properties($fits, null, null, self::definition(), self::MINIMUM, new OmissionLog, self::LARGEST_MANIFEST);

        self::assertSame(['_audit' => ['manifest' => self::LARGEST_MANIFEST, 'omitted' => ['count' => 1, 'paths' => ['*']]]], $result);
    }

    /**
     * The worst case fits the least budget: 32 distinct rule paths of 128 bytes
     * from the omissions, the largest count, an identifier hash, the largest
     * manifest descriptor and a note of 1,024 bytes that all need escaping. The
     * note fits beside the reserve even so, so it stays, and everything else
     * that could go has gone.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWorstCaseMetadataFitsTheMinimumBudget(): void
    {
        [$definition, $values] = self::worstCaseKeys();

        $log = new OmissionLog;

        $log->addCount(PHP_INT_MAX);

        $note   = str_repeat('"', 1024);
        $result = ByteBudget::properties($values, $note, self::HASH, $definition, self::MINIMUM, $log, self::LARGEST_MANIFEST);

        self::assertSame(['_audit'], array_keys($result ?? []));
        self::assertSame($note, $result['_audit']['note'] ?? null);
        self::assertSame(self::HASH, $result['_audit']['identifier_hash'] ?? null);
        self::assertSame(self::LARGEST_MANIFEST, $result['_audit']['manifest'] ?? null);
        self::assertSame(PHP_INT_MAX, $result['_audit']['omitted']['count'] ?? null);
        self::assertCount(32, self::omittedPathsOf($result));
        self::assertLessThanOrEqual(self::MINIMUM, strlen(self::encoded($result)));
    }

    /**
     * The worst case still fits with a note too large to stay, which only an
     * envelope can be: the note goes, and the hash, the manifest descriptor and
     * the list do not. Its path sorts after the 32 already held, so only the
     * count records it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWorstCaseMetadataFitsWithTheNoteOmitted(): void
    {
        [$definition, $values] = self::worstCaseKeys();

        $log = new OmissionLog;

        $log->addCount(PHP_INT_MAX);

        $result = ByteBudget::properties($values, ['v' => 1, 'k' => 'key', 'c' => str_repeat('"', 4096)], self::HASH, $definition, self::MINIMUM, $log, self::LARGEST_MANIFEST);

        self::assertArrayNotHasKey('note', self::auditOf($result));
        self::assertSame(self::HASH, $result['_audit']['identifier_hash'] ?? null);
        self::assertSame(self::LARGEST_MANIFEST, $result['_audit']['manifest'] ?? null);
        self::assertCount(32, self::omittedPathsOf($result));
        self::assertLessThanOrEqual(self::MINIMUM, strlen(self::encoded($result)));
    }

    /**
     * The tightest case fits too: the worst metadata beside a key and a note
     * that cost exactly what the reserve leaves, so no spare byte hides a bad
     * reserve.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWorstCaseFitsBesideKeysAtTheLimit(): void
    {
        [$definition, $values] = self::worstCaseKeys();

        $log = new OmissionLog;

        $log->addCount(PHP_INT_MAX);

        $note = str_repeat('"', 1024);

        $values['keep'] = self::costing('keep', self::MINIMUM_LIMIT - 2058);

        $result = ByteBudget::properties($values, $note, self::HASH, $definition->retain('keep'), self::MINIMUM, $log, self::LARGEST_MANIFEST);

        self::assertArrayHasKey('keep', $result ?? []);
        self::assertSame($note, $result['_audit']['note'] ?? null);
        self::assertSame(self::LARGEST_MANIFEST, $result['_audit']['manifest'] ?? null);
        self::assertCount(32, self::omittedPathsOf($result));
        self::assertLessThanOrEqual(self::MINIMUM, strlen(self::encoded($result)));
        self::assertGreaterThan(self::MINIMUM - ByteBudget::METADATA_RESERVE_BYTES, strlen(self::encoded($result)));
    }

    /**
     * The same input gives the same result, the same log included.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testOmissionIsDeterministic(): void
    {
        $values = self::mixedPayload();

        $firstLog  = new OmissionLog;
        $secondLog = new OmissionLog;

        $first  = ByteBudget::properties($values, 'Checked', self::HASH, self::definition()->retain('ruled'), self::MINIMUM, $firstLog);
        $second = ByteBudget::properties($values, 'Checked', self::HASH, self::definition()->retain('ruled'), self::MINIMUM, $secondLog);

        self::assertSame($first, $second);
        self::assertSame($firstLog->toArray(), $secondLog->toArray());
    }

    /**
     * The same keys in another order leave the same keys and the same
     * diagnostics, because selection depends only on tiers, costs and keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testOmissionIgnoresTheInputOrderOfKeys(): void
    {
        $values     = self::mixedPayload();
        $definition = self::definition()->retain('ruled');

        $reversed = array_reverse($values, true);
        $sorted   = $values;

        ksort($sorted);

        $rotated = array_slice($values, 2, null, true) + array_slice($values, 0, 2, true);

        $baseline = new OmissionLog;
        $expected = ByteBudget::properties($values, 'Checked', self::HASH, $definition, self::MINIMUM, $baseline);
        $keys     = array_keys($expected ?? []);

        sort($keys);

        foreach ([$reversed, $sorted, $rotated] as $reordered) {
            $log    = new OmissionLog;
            $result = ByteBudget::properties($reordered, 'Checked', self::HASH, $definition, self::MINIMUM, $log);
            $found  = array_keys($result ?? []);

            sort($found);

            self::assertSame($keys, $found);
            self::assertSame($baseline->toArray(), $log->toArray());
            self::assertSame($expected['_audit'] ?? null, $result['_audit'] ?? null);
        }
    }

    /**
     * Sizes are measured as the row stores them: multi-byte characters and
     * slashes are not escaped, so a payload of them fits where an escaped
     * encoding would not, and is costed at its stored size when choosing.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testCostsAreMeasuredWithTheFixedFlags(): void
    {
        $unicode = ['a' => str_repeat('é', 4092)];
        $slashes = ['a' => str_repeat('/', self::MINIMUM - 8)];

        self::assertSame($unicode, ByteBudget::properties($unicode, null, null, self::definition(), self::MINIMUM, new OmissionLog));
        self::assertSame($slashes, ByteBudget::properties($slashes, null, null, self::definition(), self::MINIMUM, new OmissionLog));

        foreach (['/', 'é'] as $character) {
            $repeats = (int) (3000 / strlen($character));
            $values  = ['a' => str_repeat($character, $repeats), 'b' => str_repeat('x', 5500)];

            $result = ByteBudget::properties($values, null, null, self::definition(), self::MINIMUM, new OmissionLog);

            self::assertSame(['a', '_audit'], array_keys($result ?? []), $character);
        }
    }

    /**
     * A numeric key is costed and compared as the string it is stored as: with
     * equal costs `10` goes before `9`, which comparing numbers would reverse.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testANumericKeyIsCostedAsAString(): void
    {
        $values = [9 => self::costing('9', 4600), 10 => self::costing('10', 4600)];

        $result = ByteBudget::properties($values, null, null, self::definition(), 9200, new OmissionLog);

        self::assertSame([9, '_audit'], array_keys($result ?? []));

        $context = [9 => self::costing('9', 600), 10 => self::costing('10', 600)];

        self::assertSame([9], array_keys(ByteBudget::context($context, self::CONTEXT_MINIMUM, new OmissionLog) ?? []));
    }

    /**
     * A numeric key a rule names is reported by that name, as a string, and a
     * numeric key no rule names is masked.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnOmittedNumericKeyIsMaskedAsAnyOther(): void
    {
        $log = new OmissionLog;

        ByteBudget::properties([5 => str_repeat('x', self::MINIMUM), 6 => str_repeat('x', self::MINIMUM)], null, null, self::definition()->drop('5'), self::MINIMUM, $log);

        self::assertSame(['count' => 2, 'paths' => ['*', '5']], $log->toArray());
    }

    /**
     * Integer keys keep their values and their numbers beside the metadata, so
     * a list of properties is not renumbered or lost to a merge.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testIntegerKeysKeepTheirValuesBesideTheMetadata(): void
    {
        $metadata = ['identifier_hash' => self::HASH];

        $sparse = ByteBudget::properties([5 => 'a', 7 => 'b'], null, self::HASH, self::definition(), self::MINIMUM, new OmissionLog);
        $list   = ByteBudget::properties(['a', 'b'], null, self::HASH, self::definition(), self::MINIMUM, new OmissionLog);

        self::assertSame([5 => 'a', 7 => 'b', '_audit' => $metadata], $sparse);
        self::assertSame(['a', 'b', '_audit' => $metadata], $list);
    }

    /**
     * Paths logged before the budget ran are kept and counted with its own, so
     * the single list holds everything the capture removed.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEarlierOmissionsAreKeptBesideItsOwn(): void
    {
        $log = new OmissionLog;

        $log->add('context.*');
        $log->addCount(3);

        $result = ByteBudget::properties(['a' => str_repeat('x', self::MINIMUM)], null, null, self::definition(), self::MINIMUM, $log);

        self::assertSame(['_audit' => ['omitted' => ['count' => 5, 'paths' => ['*', 'context.*']]]], $result);
    }

    /**
     * The context fits its budget with no reserve: the bytes it would keep for
     * metadata stay available, so a key costing all but its braces is kept at
     * the exact limit.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheContextBudgetFitsAndNeedsNoReserve(): void
    {
        $log    = new OmissionLog;
        $values = ['big' => self::costing('big', 2000), 'small' => self::costing('small', self::CONTEXT_MINIMUM - 1)];

        $result = ByteBudget::context($values, self::CONTEXT_MINIMUM, $log);

        self::assertSame(['small' => $values['small']], $result);
        self::assertSame(self::CONTEXT_MINIMUM, strlen(self::encoded($result)));
        self::assertSame(['count' => 1, 'paths' => ['context.*']], $log->toArray());
    }

    /**
     * Costs summing to the budget encode one byte over it, because the two
     * braces outweigh the last key's missing comma, so a key goes; costs one
     * byte less encode exactly to the budget, so none does. The limit on the
     * remaining cost is one under the budget, not the budget.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheContextBudgetCountsItsBraces(): void
    {
        $over = ['a' => self::costing('a', 600), 'b' => self::costing('b', self::CONTEXT_MINIMUM - 600)];
        $log  = new OmissionLog;

        $result = ByteBudget::context($over, self::CONTEXT_MINIMUM, $log);

        self::assertSame(['b' => $over['b']], $result);
        self::assertLessThanOrEqual(self::CONTEXT_MINIMUM, strlen(self::encoded($result)));
        self::assertSame(1, $log->toArray()['count'] ?? null);

        $fits = ['a' => self::costing('a', 600), 'b' => self::costing('b', self::CONTEXT_MINIMUM - 601)];
        $log  = new OmissionLog;

        $result = ByteBudget::context($fits, self::CONTEXT_MINIMUM, $log);

        self::assertSame($fits, $result);
        self::assertSame(self::CONTEXT_MINIMUM, strlen(self::encoded($result)));
        self::assertNull($log->toArray());

        $tight = ['large' => self::costing('large', self::CONTEXT_MINIMUM), 'a' => self::costing('a', 512), 'b' => self::costing('b', self::CONTEXT_MINIMUM - 512)];
        $log   = new OmissionLog;

        $result = ByteBudget::context($tight, self::CONTEXT_MINIMUM, $log);

        self::assertLessThanOrEqual(self::CONTEXT_MINIMUM, strlen(self::encoded($result)));
        self::assertSame(['b'], array_keys($result ?? []));
    }

    /**
     * A list encodes without its keys, so its real encoding decides whether it
     * fits, not the costs, which count keys it does not store: one that encodes
     * to exactly the budget comes back whole, and one byte more loses elements.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAContextListWithinBudgetIsUntouched(): void
    {
        $log  = new OmissionLog;
        $list = [...array_fill(0, 254, 'x'), 'xxxx'];

        self::assertSame(self::CONTEXT_MINIMUM, strlen(self::encoded($list)));
        self::assertSame($list, ByteBudget::context($list, self::CONTEXT_MINIMUM, $log));
        self::assertNull($log->toArray());

        $longer = [...array_fill(0, 254, 'x'), 'xxxxx'];

        $log    = new OmissionLog;
        $result = ByteBudget::context($longer, self::CONTEXT_MINIMUM, $log);

        self::assertNotSame($longer, $result);
        self::assertLessThanOrEqual(self::CONTEXT_MINIMUM, strlen(self::encoded($result)));
        self::assertGreaterThan(0, $log->toArray()['count'] ?? 0);
    }

    /**
     * An application's key goes before any name the package fills, even when it
     * is the smaller: `app` goes and the larger `route` stays.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testContextApplicationKeysGoBeforeThePackagesNames(): void
    {
        $log    = new OmissionLog;
        $values = ['route' => self::costing('route', 900), 'app' => self::costing('app', 200)];

        $result = ByteBudget::context($values, self::CONTEXT_MINIMUM, $log);

        self::assertSame(['route' => $values['route']], $result);
        self::assertSame(['count' => 1, 'paths' => ['context.*']], $log->toArray());
    }

    /**
     * A name the package fills is reported literally when it goes, and goes
     * only once every application key has.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testContextPackageNamesAreLiteralWhenOmitted(): void
    {
        $log    = new OmissionLog;
        $values = ['route' => self::costing('route', 2000), 'bob@example.com' => self::costing('bob@example.com', 200)];

        $result = ByteBudget::context($values, self::CONTEXT_MINIMUM, $log);

        self::assertNull($result);
        self::assertSame(['count' => 2, 'paths' => ['context.*', 'context.route']], $log->toArray());
    }

    /**
     * Rows of `[key]`: each name the package fills, all of them tier one.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePackageNames(): iterable
    {
        yield from [
            'route'   => ['route'],
            'method'  => ['method'],
            'command' => ['command'],
            'job'     => ['job'],
            'channel' => ['channel'],
        ];
    }

    /**
     * Every fixed name outlasts an application key smaller than it.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('providePackageNames')]
    public function testEachPackageNameOutlastsAnApplicationKey(string $name): void
    {
        $values = [$name => self::costing($name, 900), 'zz' => self::costing('zz', 200)];

        self::assertSame([$name], array_keys(ByteBudget::context($values, self::CONTEXT_MINIMUM, new OmissionLog) ?? []));
    }

    /**
     * Within a tier the context goes largest first and then bytewise, as the
     * properties do.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testContextKeysGoLargestFirstThenBytewise(): void
    {
        $values = ['small' => self::costing('small', 100), 'large' => self::costing('large', 1000)];

        self::assertSame(['small'], array_keys(ByteBudget::context($values, self::CONTEXT_MINIMUM, new OmissionLog) ?? []));

        $tied = ['b' => self::costing('b', 600), 'a' => self::costing('a', 600)];

        self::assertSame(['b'], array_keys(ByteBudget::context($tied, self::CONTEXT_MINIMUM, new OmissionLog) ?? []));
    }

    /**
     * `_audit` means nothing special in a context: it is kept like any key when
     * it fits, and goes first like any application key when it does not.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testContextAuditIsAnOrdinaryKey(): void
    {
        $log = new OmissionLog;

        self::assertSame(['_audit' => ['note' => 'x']], ByteBudget::context(['_audit' => ['note' => 'x']], self::CONTEXT_MINIMUM, $log));
        self::assertNull($log->toArray());

        $values = ['_audit' => self::costing('_audit', 200), 'route' => self::costing('route', 900)];

        self::assertSame(['route' => $values['route']], ByteBudget::context($values, self::CONTEXT_MINIMUM, $log));
        self::assertSame(['count' => 1, 'paths' => ['context.*']], $log->toArray());
    }

    /**
     * What a context loses is reported in the one log, never inside the context
     * itself, which stays the caller's keys alone.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheContextHoldsNoDiagnostics(): void
    {
        $log    = new OmissionLog;
        $values = ['big' => str_repeat('x', 2000), 'small' => 'kept'];

        self::assertSame(['small' => 'kept'], ByteBudget::context($values, self::CONTEXT_MINIMUM, $log));
        self::assertSame(1, $log->toArray()['count'] ?? null);
    }

    /**
     * A value or a key that cannot be encoded fails with no payload in the
     * message or in any frame, even with every frame keeping its arguments and
     * `json_encode()` being unable to mark its own as sensitive.
     *
     * @return void
     */
    public function testAnEncodingFailureCarriesNoPayload(): void
    {
        $calls = [
            static fn (): ?array => ByteBudget::properties(['budget-planted-key' => "budget-planted-value\xB1"], null, null, self::definition(), self::MINIMUM, new OmissionLog),
            static fn (): ?array => ByteBudget::properties(["budget-planted-key\xB1" => 'budget-planted-value'], null, null, self::definition(), self::MINIMUM, new OmissionLog),
            static fn (): ?array => ByteBudget::properties([], "budget-planted-note\xB1", null, self::definition(), self::MINIMUM, new OmissionLog),
            static fn (): ?array => ByteBudget::context(['budget-planted-key' => "budget-planted-value\xB1"], self::CONTEXT_MINIMUM, new OmissionLog),
            static fn (): ?array => ByteBudget::context(["budget-planted-key\xB1" => 'budget-planted-value'], self::CONTEXT_MINIMUM, new OmissionLog),
        ];

        foreach ($calls as $call) {
            $ignored = ini_set('zend.exception_ignore_args', '0');

            try {
                $call();

                self::fail('Expected the payload to be refused.');
            } catch (\JsonException $exception) {
                self::assertSame('A value that cannot be encoded cannot be measured.', $exception->getMessage());
                self::assertNull($exception->getPrevious());
                self::assertStringNotContainsString('budget-planted', print_r($exception->getTrace(), true));
                self::assertStringNotContainsString('budget-planted', (string) $exception);
            } finally {
                ini_set('zend.exception_ignore_args', (string) $ignored);
            }
        }
    }

    /**
     * The definition most tests omit under, with no rules.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    private static function definition(): EventDefinition
    {
        return EventDefinition::for('invoice.approved');
    }

    /**
     * A string whose key and value together cost exactly the bytes given: the
     * encoded key, a colon, the encoded value and a comma, for a key and value
     * that need no escaping.
     *
     * @param  string  $key
     * @param  int  $cost
     * @return string
     */
    private static function costing(string $key, int $cost): string
    {
        return str_repeat('x', $cost - strlen($key) - 6);
    }

    /**
     * The package's reserved properties of the result, or none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $result
     * @return array<array-key, mixed>
     */
    private static function auditOf(?array $result): array
    {
        $audit = $result['_audit'] ?? [];

        self::assertIsArray($audit);

        return $audit;
    }

    /**
     * The paths the result records as omitted, or none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $result
     * @return array<array-key, mixed>
     */
    private static function omittedPathsOf(?array $result): array
    {
        $omitted = self::auditOf($result)['omitted'] ?? [];

        self::assertIsArray($omitted);

        $paths = $omitted['paths'] ?? [];

        self::assertIsArray($paths);

        return $paths;
    }

    /**
     * What the payload encodes to, as it is stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \JsonException
     */
    private static function encoded(mixed $value): string
    {
        return json_encode($value, CanonicalEncoder::JSON_FLAGS);
    }

    /**
     * A definition with 32 rules of 128 bytes, and a payload with a key for
     * each too large for even one of them to stay, so every path reaches the
     * log.
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Definitions\EventDefinition, 1: array<string, string>}
     */
    private static function worstCaseKeys(): array
    {
        $definition = self::definition();
        $values     = [];

        foreach (range(1, OmissionLog::MAX_PATHS) as $index) {
            $key = str_pad((string) $index, OmissionLog::MAX_PATH_BYTES, 'k');

            $definition   = $definition->drop($key);
            $values[$key] = str_repeat('x', 4000);
        }

        return [$definition, $values];
    }

    /**
     * Keys of every kind the budget tells apart, in an order no sort gives.
     *
     * @return array<string, string>
     */
    private static function mixedPayload(): array
    {
        return [
            'mango'  => str_repeat('x', 3000),
            'apple'  => str_repeat('x', 3000),
            'ruled'  => str_repeat('x', 2000),
            'cherry' => str_repeat('x', 1500),
            'date'   => str_repeat('x', 500),
            'banana' => str_repeat('x', 1500),
        ];
    }
}
