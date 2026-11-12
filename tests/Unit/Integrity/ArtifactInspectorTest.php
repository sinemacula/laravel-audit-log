<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\ArtifactInspector;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for classifying a stored artifact against its signed descriptor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ArtifactInspector::class)]
final class ArtifactInspectorTest extends TestCase
{
    /** @var string The artifact id the descriptor signs. */
    private const string ARTIFACT_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string An artifact id the descriptor does not sign. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var string The entry that signs the descriptor. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-00000000f0f0';

    /** @var string An entry that does not sign the descriptor. */
    private const string OTHER_ENTRY = '01932b4e-8a40-7000-8000-00000000f0f1';

    /** @var string The digest the descriptor signs. */
    private const string DIGEST = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** @var string A digest the descriptor does not sign. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * Rows of `[value, whether it is a descriptor]`: an artifact id, a known
     * kind, a digest and a count, in any key order, and nothing else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: bool}>
     */
    public static function provideDescriptors(): iterable
    {
        $valid = self::descriptor();

        yield from [
            'a bulk operation'            => [$valid, true],
            'in another key order'        => [['count' => 3, 'digest' => self::DIGEST, 'kind' => 'bulk', 'artifact_id' => self::ARTIFACT_ID], true],
            'an empty disclosure'         => [['kind' => 'disclosure', 'count' => 0] + $valid, true],
            'an empty export'             => [['kind' => 'export', 'count' => 0] + $valid, true],
            'a disclosure'                => [['kind' => 'disclosure', 'count' => 500] + $valid, true],
            'a bulk of one'               => [['count' => 1] + $valid, true],
            'empty'                       => [[], false],
            'a list'                      => [[self::ARTIFACT_ID, 'bulk', self::DIGEST, 3], false],
            'no artifact id'              => [array_diff_key($valid, ['artifact_id' => true]), false],
            'no kind'                     => [array_diff_key($valid, ['kind' => true]), false],
            'no digest'                   => [array_diff_key($valid, ['digest' => true]), false],
            'no count'                    => [array_diff_key($valid, ['count' => true]), false],
            'an extra key'                => [$valid + ['extra' => 1], false],
            'an unknown kind'             => [['kind' => 'audit'] + $valid, false],
            'an upper-case kind'          => [['kind' => 'BULK'] + $valid, false],
            'a kind not a string'         => [['kind' => 1] + $valid, false],
            'an upper-case artifact id'   => [['artifact_id' => strtoupper(self::ARTIFACT_ID)] + $valid, false],
            'an artifact id not a UUID'   => [['artifact_id' => 'artifact'] + $valid, false],
            'an artifact id not a string' => [['artifact_id' => 7] + $valid, false],
            'an upper-case digest'        => [['digest' => strtoupper(self::DIGEST)] + $valid, false],
            'a short digest'              => [['digest' => substr(self::DIGEST, 1)] + $valid, false],
            'a digest not a string'       => [['digest' => 7] + $valid, false],
            'an empty bulk'               => [['count' => 0] + $valid, false],
            'a negative bulk'             => [['count' => -1] + $valid, false],
            'a negative disclosure'       => [['kind' => 'disclosure', 'count' => -1] + $valid, false],
            'a negative export'           => [['kind' => 'export', 'count' => -1] + $valid, false],
            'a count as a string'         => [['count' => '3'] + $valid, false],
            'a count as a float'          => [['count' => 3.0] + $valid, false],
        ];
    }

    /**
     * A value is a descriptor exactly when it holds the four keys, each of its
     * kind, and the count its kind allows.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideDescriptors')]
    public function testIsDescriptor(array $descriptor, bool $expected): void
    {
        self::assertSame($expected, ArtifactInspector::isDescriptor($descriptor));
    }

    /**
     * Rows of `[stored columns, finding]`: each difference alone and, where two
     * combine, the one checked first.
     *
     * @return iterable<string, array{0: ?array<string, scalar|null>, 1: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideStoredColumns(): iterable
    {
        $stored = self::stored();

        yield from [
            'missing'                         => [null, Finding::MANIFEST_MISSING],
            'swapped id'                      => [['id' => self::OTHER_ID] + $stored, Finding::MANIFEST_SWAPPED],
            'swapped entry'                   => [['entry_id' => self::OTHER_ENTRY] + $stored, Finding::MANIFEST_SWAPPED],
            'no id'                           => [array_diff_key($stored, ['id' => true]), Finding::MANIFEST_SWAPPED],
            'no entry'                        => [array_diff_key($stored, ['entry_id' => true]), Finding::MANIFEST_SWAPPED],
            'wrong kind'                      => [['kind' => 'export'] + $stored, Finding::MANIFEST_WRONG_KIND],
            'no kind'                         => [['kind' => null] + $stored, Finding::MANIFEST_WRONG_KIND],
            'mismatched count'                => [['member_count' => 4] + $stored, Finding::MANIFEST_MISMATCH],
            'mismatched count as a string'    => [['member_count' => '4'] + $stored, Finding::MANIFEST_MISMATCH],
            'a count that is no integer'      => [['member_count' => '3.0'] + $stored, Finding::MANIFEST_MISMATCH],
            'mismatched digest'               => [['digest' => self::OTHER_DIGEST] + $stored, Finding::MANIFEST_MISMATCH],
            'swapped and of another kind'     => [['id' => self::OTHER_ID, 'kind' => 'export'] + $stored, Finding::MANIFEST_SWAPPED],
            'of another kind and count'       => [['kind' => 'export', 'member_count' => 4] + $stored, Finding::MANIFEST_WRONG_KIND],
            'the matching row'                => [$stored, null],
            'the matching row, count as text' => [['member_count' => '3'] + $stored, null],
        ];
    }

    /**
     * Each difference of the stored columns gives its finding in order:
     * missing, swapped, wrong kind, then mismatch.
     *
     * @param  ?array<string, scalar|null>  $stored
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $expected
     * @return void
     */
    #[DataProvider('provideStoredColumns')]
    public function testEachColumnsFinding(?array $stored, ?Finding $expected): void
    {
        self::assertSame($expected, ArtifactInspector::columnsFinding($stored, self::ENTRY_ID, self::descriptor()));
    }

    /**
     * Rows of `[kind, plaintext, signed count, signed digest, finding]`, for
     * every kind.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind, 1: string, 2: int, 3: string, 4: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function providePlaintexts(): iterable
    {
        foreach (ArtifactKind::cases() as $kind) {
            $canonical = RecordFactory::canonical($kind, 2);
            $other     = RecordFactory::canonical($kind, 3);
            $foreign   = RecordFactory::canonical($kind === ArtifactKind::BULK ? ArtifactKind::DISCLOSURE : ArtifactKind::BULK, 2);
            $digest    = hash('sha256', $canonical);

            yield from [
                $kind->value . ': canonical'                => [$kind, $canonical, 2, $digest, null],
                $kind->value . ': malformed'                => [$kind, 'not json', 2, $digest, Finding::MANIFEST_MALFORMED],
                $kind->value . ': spaced'                   => [$kind, ' ' . $canonical, 2, $digest, Finding::MANIFEST_MALFORMED],
                $kind->value . ': empty'                    => [$kind, '', 2, $digest, Finding::MANIFEST_MALFORMED],
                $kind->value . ': another kind'             => [$kind, $foreign, 2, hash('sha256', $foreign), Finding::MANIFEST_MALFORMED],
                $kind->value . ': tampered count'           => [$kind, $canonical, 3, $digest, Finding::MANIFEST_TAMPERED],
                $kind->value . ': tampered digest'          => [$kind, $canonical, 2, self::OTHER_DIGEST, Finding::MANIFEST_TAMPERED],
                $kind->value . ': another canonical form'   => [$kind, $other, 2, $digest, Finding::MANIFEST_TAMPERED],
                $kind->value . ': another form, its digest' => [$kind, $other, 2, hash('sha256', $other), Finding::MANIFEST_TAMPERED],
            ];
        }
    }

    /**
     * A plaintext the signed kind cannot read is malformed, another canonical
     * form of the kind is tampered, and the signed form gives no finding.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $plaintext
     * @param  int  $count
     * @param  string  $digest
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $expected
     * @return void
     */
    #[DataProvider('providePlaintexts')]
    public function testEachPlaintextFinding(ArtifactKind $kind, string $plaintext, int $count, string $digest, ?Finding $expected): void
    {
        $descriptor = ['artifact_id' => self::ARTIFACT_ID, 'kind' => $kind->value, 'digest' => $digest, 'count' => $count];

        self::assertSame($expected, ArtifactInspector::plaintextFinding($plaintext, $descriptor));
    }

    /**
     * An empty disclosure and an export of no line, each the canonical form of
     * the empty set, give no finding.
     *
     * @return void
     */
    public function testAnEmptyArtifactHasNoFinding(): void
    {
        foreach ([ArtifactKind::DISCLOSURE, ArtifactKind::EXPORT] as $kind) {
            $canonical  = RecordFactory::canonical($kind, 0);
            $descriptor = ['artifact_id' => self::ARTIFACT_ID, 'kind' => $kind->value, 'digest' => hash('sha256', $canonical), 'count' => 0];

            self::assertNull(ArtifactInspector::plaintextFinding($canonical, $descriptor), $kind->value);
        }
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ArtifactInspector::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ArtifactInspector::class, $instance);
    }

    /**
     * The bulk descriptor the stored columns are checked against.
     *
     * @return array{artifact_id: string, count: int, digest: string, kind: string}
     */
    private static function descriptor(): array
    {
        return ['artifact_id' => self::ARTIFACT_ID, 'kind' => 'bulk', 'digest' => self::DIGEST, 'count' => 3];
    }

    /**
     * The stored columns of the artifact the descriptor signed, as an engine
     * returns them.
     *
     * @return array<string, scalar|null>
     */
    private static function stored(): array
    {
        return ['id' => self::ARTIFACT_ID, 'entry_id' => self::ENTRY_ID, 'kind' => 'bulk', 'member_count' => 3, 'digest' => self::DIGEST, 'members_length' => 120];
    }
}
