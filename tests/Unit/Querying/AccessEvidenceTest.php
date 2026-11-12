<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Querying\AccessEvidence;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\FieldDisclosure;
use SineMacula\Laravel\AuditLog\Querying\Position;
use SineMacula\Laravel\AuditLog\Querying\ReadTerms;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\DisclosureManifest;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the evidence the record of a read must keep.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessEvidence::class)]
final class AccessEvidenceTest extends TestCase
{
    /** @var string The id of the key the reads are fingerprinted under. */
    private const string KEY_ID = 'reads-1';

    /** @var string The policy the reads name. */
    private const string POLICY = 'App\Audit\TeamPolicy';

    /** @var string The id of an entry a read returned. */
    private const string FIRST_ID = '0192f0c1-7e2a-7b3c-8d4e-5f6a7b8c9d0e';

    /** @var string The id of another entry a read returned. */
    private const string SECOND_ID = '0192f0c1-7e2a-7b3c-8d4e-5f6a7b8c9d0f';

    /** @var string The time of a position. */
    private const string TIME = '2026-11-01T12:00:00.123456Z';

    /** @var string The refusal of a record that would not keep the evidence. */
    private const string ALTERED = 'The record of the read of the audit trail would not keep its evidence exactly, so the read was refused.';

    /**
     * Rows of `[evidence, property keys, manifest kind]`, one per constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Querying\AccessEvidence, 1: list<string>, 2: ?\SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideReadCodes(): iterable
    {
        yield from [
            'a page' => [
                static fn (): AccessEvidence => self::page(),
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'reveal', 'fields', 'outcome'],
                ArtifactKind::DISCLOSURE,
            ],
            'a count' => [
                static fn (): AccessEvidence => AccessEvidence::forCount(self::terms(self::scope()), self::POLICY, 12, Outcome::SUCCESS),
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'returned', 'outcome'],
                ArtifactKind::DISCLOSURE,
            ],
            'an export' => [
                static fn (): AccessEvidence => self::export(Outcome::SUCCESS),
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'format', 'returned', 'file_sha256', 'outcome'],
                ArtifactKind::EXPORT,
            ],
            'a verification' => [
                static fn (): AccessEvidence => AccessEvidence::forVerification(self::verified(self::scope()), self::POLICY, self::entry(), [], Outcome::SUCCESS),
                ['purpose', 'scope_fingerprint', 'fingerprint_key', 'policy', 'export_entry', 'verdict', 'findings', 'outcome'],
                ArtifactKind::DISCLOSURE,
            ],
            'a publish failure' => [
                static fn (): AccessEvidence => AccessEvidence::forPublishFailure(self::FIRST_ID),
                ['export_entry', 'outcome'],
                null,
            ],
        ];
    }

    /**
     * Each read code's evidence holds exactly its properties, in order.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Querying\AccessEvidence  $evidence
     * @param  list<string>  $keys
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @return void
     */
    #[DataProvider('provideReadCodes')]
    public function testTheReadPropertiesAreExactlyThese(\Closure $evidence, array $keys, ?ArtifactKind $kind): void
    {
        $made = $evidence();

        self::assertSame($keys, array_keys($made->properties));
        self::assertSame($kind, $made->manifest?->kind);
    }

    /**
     * The values each read code's properties keep.
     *
     * @return void
     */
    public function testTheReadPropertiesHoldTheirValues(): void
    {
        $count        = AccessEvidence::forCount(self::terms(self::scope()), self::POLICY, 12, Outcome::SUCCESS);
        $export       = self::export(Outcome::DENIED);
        $verification = AccessEvidence::forVerification(self::verified(self::scope()), self::POLICY, [self::FIRST_ID, self::hmac('a')], ['entry_hmac_mismatch'], Outcome::SUCCESS);
        $failure      = AccessEvidence::forPublishFailure(self::FIRST_ID);

        $page = self::page();

        self::assertSame(['read', self::POLICY, 25, 2, 'success'], [
            $page->properties['purpose'],
            $page->properties['policy'],
            $page->properties['per_page'],
            $page->properties['returned'],
            $page->properties['outcome'],
        ]);
        self::assertSame(['count', 12, 'success'], [$count->properties['purpose'], $count->properties['returned'], $count->properties['outcome']]);
        self::assertSame(['export', 'ndjson', 0, self::hmac('f'), 'denied'], [
            $export->properties['purpose'],
            $export->properties['format'],
            $export->properties['returned'],
            $export->properties['file_sha256'],
            $export->properties['outcome'],
        ]);
        self::assertSame(['verify', self::FIRST_ID, 'not_verified', ['entry_hmac_mismatch'], 'success'], [
            $verification->properties['purpose'],
            $verification->properties['export_entry'],
            $verification->properties['verdict'],
            $verification->properties['findings'],
            $verification->properties['outcome'],
        ]);
        self::assertSame(['export_entry' => self::FIRST_ID, 'outcome' => 'failure'], $failure->properties);
        self::assertNull($failure->manifest);
    }

    /**
     * The fingerprints are the keyed ones; the scope's is `null` if unanswered.
     *
     * @return void
     */
    public function testTheFingerprintsAreTheKeyedOnes(): void
    {
        $page   = self::page();
        $failed = AccessEvidence::forCount(self::terms(null), self::POLICY, 0, Outcome::FAILURE);
        $terms  = self::terms(self::scope());

        self::assertSame([$terms->queryFingerprint, $terms->scopeFingerprint, self::KEY_ID], [
            $page->properties['query_fingerprint'],
            $page->properties['scope_fingerprint'],
            $page->properties['fingerprint_key'],
        ]);
        self::assertNotSame(hash('sha256', CanonicalEncoder::encode(self::filters()->normalised())), $page->properties['query_fingerprint']);
        self::assertNotSame(hash('sha256', CanonicalEncoder::encode(self::scope()->toArray())), $page->properties['scope_fingerprint']);
        self::assertNull($failed->properties['scope_fingerprint']);
        self::assertSame($terms->queryFingerprint, $failed->properties['query_fingerprint']);
    }

    /**
     * Rows of `[scope, cursor presented, position, page shown]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Access\AccessScope, 1: bool, 2: ?\SineMacula\Laravel\AuditLog\Querying\Position, 3: array{occurred_at: string, id: string}|string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function providePages(): iterable
    {
        $position = new Position(self::TIME, self::SECOND_ID);

        yield from [
            'the first page'          => [static fn (): AccessScope => self::scope(), false, null, 'first'],
            'a cursor with no place'  => [static fn (): AccessScope => self::scope(), true, null, 'cursor'],
            'one tenant'              => [static fn (): AccessScope => self::scope(), true, $position, ['occurred_at' => self::TIME, 'id' => self::SECOND_ID]],
            'every tenant'            => [static fn (): AccessScope => AccessScope::all(), true, $position, 'next'],
            'a tenant and tenantless' => [static fn (): AccessScope => self::scope()->withTenantless(), true, $position, 'next'],
        ];
    }

    /**
     * A page is `first`, `cursor`, its position under one tenant, or `next`.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  bool  $cursor
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $position
     * @param  array{occurred_at: string, id: string}|string  $page
     * @return void
     */
    #[DataProvider('providePages')]
    public function testThePageIsFirstCursorThePositionOrNext(\Closure $scope, bool $cursor, ?Position $position, array|string $page): void
    {
        $evidence   = AccessEvidence::forPage(self::terms($scope()), self::POLICY, $cursor, $position, 25, [], FieldDisclosure::none(false), Outcome::SUCCESS);
        $disclosure = json_decode((string) $evidence->manifest?->canonical, true, 16, JSON_THROW_ON_ERROR);

        self::assertSame($page, $evidence->properties['page']);
        self::assertIsArray($disclosure);
        self::assertSame($position?->toArray(), $disclosure['page']);
    }

    /**
     * A page discloses its filters, scope and each returned id and HMAC.
     *
     * @return void
     */
    public function testTheDisclosureHoldsFiltersScopeAndReturnedPairs(): void
    {
        $manifest = self::page()->manifest;

        self::assertInstanceOf(Manifest::class, $manifest);

        $nonce = json_decode($manifest->canonical, true, 16, JSON_THROW_ON_ERROR)['nonce'] ?? null;

        self::assertIsString($nonce);

        $expected = CanonicalEncoder::encode([
            'disclosure_version' => 1,
            'filters'            => self::filters()->normalised(),
            'members'            => [[self::SECOND_ID, self::hmac('b')], [self::FIRST_ID, self::hmac('a')]],
            'nonce'              => $nonce,
            'page'               => null,
            'scope'              => self::scope()->toArray(),
        ]);

        self::assertSame($expected, $manifest->canonical);
        self::assertSame(2, $manifest->count);
        self::assertSame(['count' => 2, 'digest' => hash('sha256', $expected)], DisclosureManifest::read($manifest->canonical));
    }

    /**
     * A count, or a failed export, discloses filters and scope, no entry.
     *
     * @return void
     */
    public function testACountAndAFailedExportDiscloseNoEntry(): void
    {
        $count  = AccessEvidence::forCount(self::terms(self::scope()), self::POLICY, 12, Outcome::SUCCESS)->manifest;
        $export = AccessEvidence::forExport(self::terms(null), self::POLICY, 'ocsf', 40, self::hmac('f'), null, Outcome::FAILURE);

        self::assertInstanceOf(Manifest::class, $count);
        self::assertInstanceOf(Manifest::class, $export->manifest);
        self::assertSame([0, ArtifactKind::DISCLOSURE], [$count->count, $count->kind]);
        self::assertSame([0, ArtifactKind::DISCLOSURE], [$export->manifest->count, $export->manifest->kind]);
        self::assertStringContainsString('"members":[],', $export->manifest->canonical);
        self::assertStringEndsWith('"page":null,"scope":null}', $export->manifest->canonical);
        self::assertSame([0, null, 'failure'], [$export->properties['returned'], $export->properties['file_sha256'], $export->properties['outcome']]);
    }

    /**
     * Rows of `[evidence]`: denied and failed reads, each given members anyway.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Querying\AccessEvidence}>
     */
    public static function provideUnsuccessfulReads(): iterable
    {
        $page   = self::unsuccessfulPage(...);
        $verify = self::unsuccessfulVerification(...);

        yield from [
            'a denied page'         => [static fn (): AccessEvidence => $page(AccessScope::none(), Outcome::DENIED)],
            'a failed page'         => [static fn (): AccessEvidence => $page(self::scope(), Outcome::FAILURE)],
            'a denied count'        => [static fn (): AccessEvidence => AccessEvidence::forCount(self::terms(AccessScope::none()), self::POLICY, 3, Outcome::DENIED)],
            'a failed count'        => [static fn (): AccessEvidence => AccessEvidence::forCount(self::terms(self::scope()), self::POLICY, 3, Outcome::FAILURE)],
            'a failed verification' => [static fn (): AccessEvidence => $verify(self::scope(), Outcome::FAILURE)],
            'a denied verification' => [static fn (): AccessEvidence => $verify(AccessScope::none(), Outcome::DENIED)],
        ];
    }

    /**
     * A denied or failed read discloses and counts nothing.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Querying\AccessEvidence  $evidence
     * @return void
     */
    #[DataProvider('provideUnsuccessfulReads')]
    public function testADeniedOrFailedReadDisclosesNoMembers(\Closure $evidence): void
    {
        $made = $evidence();

        self::assertInstanceOf(Manifest::class, $made->manifest);
        self::assertSame(0, $made->manifest->count);
        self::assertStringContainsString('"members":[]', $made->manifest->canonical);
        self::assertSame(0, $made->properties['returned'] ?? 0);
    }

    /**
     * A page records its reveal grant and field counts outside its disclosure.
     *
     * @return void
     */
    public function testAPageRecordsItsRevealGrantAndFieldCounts(): void
    {
        $returned  = [[self::SECOND_ID, self::hmac('b')], [self::FIRST_ID, self::hmac('a')]];
        $revealing = AccessEvidence::forPage(self::terms(self::scope()), self::POLICY, false, null, 25, $returned, new FieldDisclosure(true, 4, 1, 7, 2), Outcome::SUCCESS);
        $sealed    = AccessEvidence::forPage(self::terms(self::scope()), self::POLICY, false, null, 25, $returned, new FieldDisclosure(false, 9, 0, 0, 1), Outcome::SUCCESS);

        self::assertSame(['returned', 'reveal', 'fields', 'outcome'], array_slice(array_keys($revealing->properties), -4));
        self::assertTrue($revealing->properties['reveal']);
        self::assertSame(['encrypted' => 4, 'erased' => 1, 'revealed' => 7, 'unreadable' => 2], $revealing->properties['fields']);
        self::assertFalse($sealed->properties['reveal']);
        self::assertSame(['encrypted' => 9, 'erased' => 0, 'revealed' => 0, 'unreadable' => 1], $sealed->properties['fields']);
        self::assertInstanceOf(Manifest::class, $revealing->manifest);
        self::assertSame(2, $revealing->manifest->count);

        $metadata = ['manifest' => $revealing->manifest->descriptor()];
        $altered  = [...$revealing->properties['fields'], 'revealed' => 6];

        $revealing->assertKeptBy(self::record([...$revealing->properties, '_audit' => $metadata]));

        $this->expectException(AuditReadRefusedException::class);

        $revealing->assertKeptBy(self::record([...$revealing->properties, 'fields' => $altered, '_audit' => $metadata]));
    }

    /**
     * A denied or failed page counts no fragment but records its grant.
     *
     * @return void
     */
    public function testADeniedPageCountsNoField(): void
    {
        $none = ['encrypted' => 0, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0];

        $denied  = self::unsuccessfulPage(AccessScope::none(), Outcome::DENIED);
        $failed  = self::unsuccessfulPage(self::scope()->revealingEncryptedFields(), Outcome::FAILURE, true);
        $refused = self::unsuccessfulPage(self::scope(), Outcome::DENIED, true);

        self::assertSame([false, $none, 0], [$denied->properties['reveal'], $denied->properties['fields'], $denied->properties['returned']]);
        self::assertSame([true, $none, 0], [$failed->properties['reveal'], $failed->properties['fields'], $failed->properties['returned']]);
        self::assertSame([true, $none, 0], [$refused->properties['reveal'], $refused->properties['fields'], $refused->properties['returned']]);
    }

    /**
     * A verification discloses the export entry only when it found it.
     *
     * @return void
     */
    public function testAVerificationDisclosesTheExportEntryWhenFound(): void
    {
        $found   = AccessEvidence::forVerification(self::verified(self::scope()), self::POLICY, [self::FIRST_ID, self::hmac('a')], [], Outcome::SUCCESS);
        $missing = AccessEvidence::forVerification(self::verified(self::scope()), self::POLICY, null, ['entry_missing', 'file_digest_mismatch'], Outcome::SUCCESS);

        self::assertInstanceOf(Manifest::class, $found->manifest);
        self::assertSame(1, $found->manifest->count);
        self::assertStringContainsString('"members":[["' . self::FIRST_ID . '","' . self::hmac('a') . '"]]', $found->manifest->canonical);
        self::assertSame('verified', $found->properties['verdict']);
        self::assertSame(0, $missing->manifest?->count);
        self::assertNull($missing->properties['export_entry']);
        self::assertSame(['not_verified', ['entry_missing', 'file_digest_mismatch']], [$missing->properties['verdict'], $missing->properties['findings']]);
    }

    /**
     * A successful or denied export carries its manifest as given.
     *
     * @return void
     */
    public function testAnExportCarriesItsManifest(): void
    {
        $manifest = self::exportManifest();
        $export   = AccessEvidence::forExport(self::terms(self::scope()), self::POLICY, 'ndjson', 0, self::hmac('f'), $manifest, Outcome::DENIED);

        self::assertSame($manifest, $export->manifest);
    }

    /**
     * Rows of `[export manifest]`: none, and a manifest of another kind.
     *
     * @return iterable<string, array{0: \Closure(): ?\SineMacula\Laravel\AuditLog\Records\Manifest}>
     */
    public static function provideMissingExportManifests(): iterable
    {
        yield from [
            'none'         => [static fn (): ?Manifest => null],
            'a disclosure' => [static fn (): Manifest => DisclosureManifest::of(self::filters()->normalised(), null, [])],
        ];
    }

    /**
     * A successful export without its manifest is a programming error.
     *
     * @param  \Closure(): ?\SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @return void
     */
    #[DataProvider('provideMissingExportManifests')]
    public function testAnExportThatSucceededNeedsItsManifest(\Closure $manifest): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The evidence of an export that succeeded or was denied is its export manifest.');

        AccessEvidence::forExport(self::terms(self::scope()), self::POLICY, 'ndjson', 0, null, $manifest(), Outcome::SUCCESS);
    }

    /**
     * Rows of `[evidence made with the policy name]`, one per constructor.
     *
     * @return iterable<string, array{0: \Closure(string): \SineMacula\Laravel\AuditLog\Querying\AccessEvidence}>
     */
    public static function providePolicyNames(): iterable
    {
        $none = FieldDisclosure::none(true);
        $page = static fn (string $policy): AccessEvidence => AccessEvidence::forPage(self::terms(self::scope()), $policy, false, null, 25, [], $none, Outcome::SUCCESS);

        yield from [
            'a page'         => [$page],
            'a count'        => [static fn (string $policy): AccessEvidence => AccessEvidence::forCount(self::terms(self::scope()), $policy, 0, Outcome::SUCCESS)],
            'an export'      => [static fn (string $policy): AccessEvidence => AccessEvidence::forExport(self::terms(null), $policy, 'cef', 0, null, null, Outcome::FAILURE)],
            'a verification' => [static fn (string $policy): AccessEvidence => AccessEvidence::forVerification(self::verified(null), $policy, null, [], Outcome::FAILURE)],
        ];
    }

    /**
     * A 191-byte policy name is kept; 192 bytes refuses the read.
     *
     * @param  \Closure(string): \SineMacula\Laravel\AuditLog\Querying\AccessEvidence  $evidence
     * @return void
     */
    #[DataProvider('providePolicyNames')]
    public function testAPolicyNameTooLongRefusesTheRead(\Closure $evidence): void
    {
        $longest = str_repeat('P', AccessEvidence::MAX_POLICY_BYTES);

        self::assertSame(191, AccessEvidence::MAX_POLICY_BYTES);
        self::assertSame($longest, $evidence($longest)->properties['policy']);

        $this->expectException(AuditReadRefusedException::class);
        $this->expectExceptionMessage(self::ALTERED);

        $evidence($longest . 'P');
    }

    /**
     * A record keeps the evidence in any key order, with its descriptor.
     *
     * @return void
     */
    public function testAssertKeptByAcceptsTheEvidenceExactly(): void
    {
        $page        = self::page();
        $descriptor  = $page->manifest?->descriptor();
        $publication = AccessEvidence::forPublishFailure(self::FIRST_ID);

        $page->assertKeptBy(self::record([...$page->properties, '_audit' => ['manifest' => $descriptor]]));
        $page->assertKeptBy(self::record(['_audit' => ['manifest' => array_reverse((array) $descriptor)], ...array_reverse($page->properties)]));
        $publication->assertKeptBy(self::record($publication->properties));

        $this->addToAssertionCount(3);
    }

    /**
     * Rows of `[properties a record keeps of the page's evidence]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(array<string, array<array-key, int|string>|scalar|null>, array{artifact_id: string, kind: string, digest: string, count: int}): ?array<string, array<array-key, array<array-key, scalar>|scalar|null>|scalar|null>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideAlteredRecords(): iterable
    {
        yield from [
            'a redacted value'        => [static fn (array $p, array $d): array => [...$p, 'policy' => '[REDACTED]', '_audit' => ['manifest' => $d]]],
            'a dropped key'           => [static fn (array $p, array $d): array => [...array_diff_key($p, ['per_page' => true]), '_audit' => ['manifest' => $d]]],
            'an added key'            => [static fn (array $p, array $d): array => [...$p, 'note' => 'x', '_audit' => ['manifest' => $d]]],
            'a value of another type' => [static fn (array $p, array $d): array => [...$p, 'per_page' => '25', '_audit' => ['manifest' => $d]]],
            'a float'                 => [static fn (array $p, array $d): array => [...$p, 'per_page' => 25.0, '_audit' => ['manifest' => $d]]],
            'a reordered page'        => [static fn (array $p, array $d): array => [...$p, 'page' => [self::FIRST_ID, self::TIME], '_audit' => ['manifest' => $d]]],
            'an added _audit.omitted' => [static fn (array $p, array $d): array => [...$p, '_audit' => ['manifest' => $d, 'omitted' => ['policy']]]],
            'another descriptor'      => [static fn (array $p, array $d): array => [...$p, '_audit' => ['manifest' => [...$d, 'count' => 3]]]],
            'another artifact'        => [static fn (array $p, array $d): array => [...$p, '_audit' => ['manifest' => [...$d, 'artifact_id' => self::SECOND_ID]]]],
            'no descriptor'           => [static fn (array $p, array $d): array => $p],
            'empty metadata'          => [static fn (array $p, array $d): array => [...$p, '_audit' => []]],
            'no properties'           => [static fn (array $p, array $d): ?array => null],
        ];
    }

    /**
     * A record that keeps anything but the evidence exactly refuses the read.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(array<string, array<array-key, int|string>|scalar|null>, array{artifact_id: string, kind: string, digest: string, count: int}): ?array<string, array<array-key, array<array-key, scalar>|scalar|null>|scalar|null>  $kept
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideAlteredRecords')]
    public function testAssertKeptByRefusesAnyChange(\Closure $kept): void
    {
        $page       = self::page();
        $descriptor = $page->manifest?->descriptor();

        self::assertIsArray($descriptor);

        $this->expectException(AuditReadRefusedException::class);
        $this->expectExceptionMessage(self::ALTERED);

        $page->assertKeptBy(self::record($kept($page->properties, $descriptor)));
    }

    /**
     * Evidence without a manifest refuses a record carrying any metadata.
     *
     * @return void
     */
    public function testEvidenceWithoutAManifestRefusesAnyMetadata(): void
    {
        $evidence = AccessEvidence::forPublishFailure(self::FIRST_ID);
        $other    = self::page()->manifest?->descriptor();

        $this->expectException(AuditReadRefusedException::class);
        $this->expectExceptionMessage(self::ALTERED);

        $evidence->assertKeptBy(self::record([...$evidence->properties, '_audit' => ['manifest' => $other]]));
    }

    /**
     * The evidence of a successful first page of two entries.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AccessEvidence
     */
    private static function page(): AccessEvidence
    {
        $returned = [[self::SECOND_ID, self::hmac('b')], [self::FIRST_ID, self::hmac('a')]];

        return AccessEvidence::forPage(self::terms(self::scope()), self::POLICY, false, null, 25, $returned, FieldDisclosure::none(false), Outcome::SUCCESS);
    }

    /**
     * The evidence of an export of no line, with its manifest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return \SineMacula\Laravel\AuditLog\Querying\AccessEvidence
     */
    private static function export(Outcome $outcome): AccessEvidence
    {
        return AccessEvidence::forExport(self::terms(self::scope()), self::POLICY, 'ndjson', 0, self::hmac('f'), self::exportManifest(), $outcome);
    }

    /**
     * The manifest of an export of no line.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     */
    private static function exportManifest(): Manifest
    {
        $snapshot = ['connection' => 'testing', 'consistency' => 'deferred_read_transaction', 'database' => ':memory:', 'engine' => 'sqlite', 'table' => 'audit_log_entries'];
        $empty    = hash('sha256', '');

        $viewer = Reference::of('user', '7');

        $terms = self::terms(self::scope());

        return ExportManifest::manifestOf('ndjson', $viewer, (string) $terms->scopeFingerprint, $terms->queryFingerprint, $snapshot, 0, null, null, $empty, $empty);
    }

    /**
     * Read terms under the scope and filters given, under the fixed key.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadTerms
     */
    private static function terms(?AccessScope $scope, ?TrailFilters $filters = null): ReadTerms
    {
        return ReadTerms::of(new IntegrityKey(self::KEY_ID, str_repeat('s', 32)), $filters ?? self::filters(), $scope);
    }

    /**
     * Evidence of an unsuccessful page, given members all the same.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  bool  $reveal
     * @return \SineMacula\Laravel\AuditLog\Querying\AccessEvidence
     */
    private static function unsuccessfulPage(AccessScope $scope, Outcome $outcome, bool $reveal = false): AccessEvidence
    {
        return AccessEvidence::forPage(self::terms($scope), self::POLICY, false, null, 25, [self::entry()], new FieldDisclosure($reveal, 1, 2, 3, 4), $outcome);
    }

    /**
     * Evidence of an unsuccessful verification, given the export entry anyway.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return \SineMacula\Laravel\AuditLog\Querying\AccessEvidence
     */
    private static function unsuccessfulVerification(AccessScope $scope, Outcome $outcome): AccessEvidence
    {
        return AccessEvidence::forVerification(self::verified($scope), self::POLICY, self::entry(), [], $outcome);
    }

    /**
     * The export entry a verification found, by its id and HMAC.
     *
     * @return array{0: string, 1: string}
     */
    private static function entry(): array
    {
        return [self::FIRST_ID, self::hmac('a')];
    }

    /**
     * Verification terms under the scope, with no filters, under the fixed key.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadTerms
     */
    private static function verified(?AccessScope $scope): ReadTerms
    {
        return self::terms($scope, TrailFilters::none());
    }

    /**
     * The filters of the reads: one code.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailFilters
     */
    private static function filters(): TrailFilters
    {
        return TrailFilters::none()->withEvents(['invoice.approved']);
    }

    /**
     * The scope of the reads: one tenant.
     *
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    private static function scope(): AccessScope
    {
        return AccessScope::tenants(Reference::of('team', '1'));
    }

    /**
     * An HMAC of 64 lower-case hex, all of one character.
     *
     * @param  string  $character
     * @return string
     */
    private static function hmac(string $character): string
    {
        return str_repeat($character, 64);
    }

    /**
     * A captured record keeping the properties.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<string, mixed>  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function record(#[\SensitiveParameter] ?array $properties): AuditRecord
    {
        return RecordFactory::withFields(['properties' => $properties]);
    }
}
