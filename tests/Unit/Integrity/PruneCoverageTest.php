<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverage;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverageResult;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;

/**
 * Unit tests for what a seal's prune records account for, over the golden seal
 * of three members: a missing member covered by a valid record, one covered by
 * none, records that overlap, records of another seal, forged or under a key
 * the ring does not hold, which cover nothing, membership that was not
 * authenticated, which assigns no position, a present member covered, which is
 * read again, and several disjoint records covering together, all with nothing
 * read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneCoverage::class)]
final class PruneCoverageTest extends TestCase
{
    /** @var string The golden prune vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/prune-v2.json';

    /** @var string The golden seal's first member in member order. */
    private const string FIRST = '01932b4e-8a40-7000-8000-00000000000a';

    /** @var string The golden seal's second member in member order. */
    private const string SECOND = '01932b4e-8a40-7000-8000-00000000000b';

    /** @var string The golden seal's third member in member order. */
    private const string THIRD = '01932b4e-8a40-7000-8000-00000000000c';

    /** @var string The golden seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000003';

    /** @var string A digest no seal has. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string The id of a prune operation. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When a prune ran. */
    private const string PRUNED_AT = '2027-11-01T00:00:00.000000Z';

    /**
     * Every missing member set in a valid record is covered, in the order the
     * members were missing, with no finding, and a present member the record
     * does not set is not read again.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEveryMissingMemberCoveredIsPruned(): void
    {
        $result = self::coverage([self::THIRD, self::FIRST], [self::SECOND], [self::signed([0, 2])]);

        self::assertSame([], $result->findings);
        self::assertSame([self::THIRD, self::FIRST], $result->covered);
        self::assertSame([], $result->recheck);
    }

    /**
     * A missing member set in no valid record is `missing_entry`, at the first
     * such member in member order, and the ones a record sets are still
     * covered; with no record, none is.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMissingMemberInNoRecordIsMissingEntry(): void
    {
        $partly = self::coverage([self::SECOND, self::FIRST], [self::THIRD], [self::signed([0])]);

        self::assertSame([[Finding::MISSING_ENTRY, self::SECOND]], $partly->findings);
        self::assertSame([self::FIRST], $partly->covered);

        $none = self::coverage([self::THIRD, self::SECOND], [self::FIRST], []);

        self::assertSame([[Finding::MISSING_ENTRY, self::SECOND]], $none->findings);
        self::assertSame([], $none->covered);
    }

    /**
     * Two valid records that set one member are `prune_record` at the seal, a
     * record given twice among them, and what they set is still covered, since
     * the verdict is tampered either way.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testOverlappingRecordsAreTampered(): void
    {
        $overlapping = self::coverage([self::FIRST, self::THIRD], [self::SECOND], [self::signed([0, 2]), self::signed([2])]);

        self::assertSame([[Finding::PRUNE_RECORD, self::SEAL_ID]], $overlapping->findings);
        self::assertSame([self::FIRST, self::THIRD], $overlapping->covered);

        $record = self::signed([1]);
        $twice  = self::coverage([self::SECOND], [self::FIRST, self::THIRD], [$record, $record]);

        self::assertSame([[Finding::PRUNE_RECORD, self::SEAL_ID]], $twice->findings);
        self::assertSame([self::SECOND], $twice->covered);
    }

    /**
     * Rows of `[the field changed, its value]`: a validly signed record bound
     * to another log, seal, digest or member count than the seal's.
     *
     * @return iterable<string, array{0: string, 1: int|string}>
     */
    public static function provideOtherSeals(): iterable
    {
        yield from [
            'another log'          => ['log_id', 'app-eu-2'],
            'another seal'         => ['seal_id', '01932b4e-9000-7000-8000-000000000004'],
            'another digest'       => ['seal_digest', self::OTHER_DIGEST],
            'another member count' => ['member_count', 4],
        ];
    }

    /**
     * A validly signed record that binds anything but this seal's log, id,
     * recomputed digest and member count is `prune_record` at the seal, and
     * covers nothing, so the missing member is still `missing_entry`.
     *
     * @param  string  $field
     * @param  int|string  $value
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideOtherSeals')]
    public function testARecordOfAnotherSealCoversNothing(string $field, int|string $value): void
    {
        $result = self::coverage([self::FIRST], [self::SECOND, self::THIRD], [self::signed([0, 1, 2], [$field => $value])]);

        self::assertSame([[Finding::PRUNE_RECORD, self::SEAL_ID], [Finding::MISSING_ENTRY, self::FIRST]], $result->findings);
        self::assertSame([], $result->covered);
        self::assertSame([], $result->recheck);
    }

    /**
     * A record of exactly this seal whose signature is not the key's, or is the
     * other golden record's, is `prune_record`, and covers nothing.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAForgedRecordCoversNothing(): void
    {
        $valid = self::signed([0, 2]);

        foreach ([self::OTHER_DIGEST, self::text('prune_second_signature')] as $signature) {
            $forged = self::recordOf($valid, ['signature' => $signature]);
            $result = self::coverage([self::FIRST], [self::SECOND, self::THIRD], [$forged]);

            self::assertSame([[Finding::PRUNE_RECORD, self::SEAL_ID], [Finding::MISSING_ENTRY, self::FIRST]], $result->findings);
            self::assertSame([], $result->recheck);
        }
    }

    /**
     * A record of exactly this seal under a key the ring does not hold cannot
     * be checked: `prune_key`, covering nothing. One that binds another seal is
     * `prune_record` even so, since what it binds is checked first.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordUnderAnUnknownKeyIsUnverifiable(): void
    {
        $unknown = self::recordOf(self::signed([0]), ['key_id' => 'k2024']);
        $result  = self::coverage([self::FIRST], [self::SECOND, self::THIRD], [$unknown]);

        self::assertSame([[Finding::PRUNE_KEY, self::SEAL_ID], [Finding::MISSING_ENTRY, self::FIRST]], $result->findings);
        self::assertSame([], $result->covered);

        $mismatched = self::recordOf($unknown, ['seal_digest' => self::OTHER_DIGEST]);

        self::assertSame(Finding::PRUNE_RECORD, self::coverage([self::FIRST], [], [$mismatched])->findings[0][0]);
    }

    /**
     * Without authenticated membership no position is assigned: a valid record
     * of every member covers no missing one and puts no present one to be read
     * again.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testWithoutAuthenticMembershipNothingIsCovered(): void
    {
        $result = self::coverage([self::FIRST, self::SECOND], [self::THIRD], [self::signed([0, 1, 2])], false);

        self::assertSame([[Finding::MISSING_ENTRY, self::FIRST]], $result->findings);
        self::assertSame([], $result->covered);
        self::assertSame([], $result->recheck);
    }

    /**
     * A present member a valid record sets is put to be read again, in the
     * order given, and nothing is found of it here: whether it is gone or back
     * is the reread's to tell.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testACoveredPresentMemberIsRechecked(): void
    {
        $result = self::coverage([], [self::THIRD, self::SECOND, self::FIRST], [self::signed([0, 2])]);

        self::assertSame([], $result->findings);
        self::assertSame([], $result->covered);
        self::assertSame([self::THIRD, self::FIRST], $result->recheck);
    }

    /**
     * The golden seal's two disjoint records, made by two prunes, cover every
     * member together, and either alone leaves the other's uncovered.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testSeveralDisjointRecordsCoverTogether(): void
    {
        $first  = self::golden('first');
        $second = self::golden('second');
        $all    = [self::FIRST, self::SECOND, self::THIRD];

        $together = self::coverage($all, [], [$first, $second]);

        self::assertSame([], $together->findings);
        self::assertSame($all, $together->covered);

        self::assertSame([[Finding::MISSING_ENTRY, self::SECOND]], self::coverage($all, [], [$first])->findings);
        self::assertSame([[Finding::MISSING_ENTRY, self::FIRST]], self::coverage($all, [], [$second])->findings);
    }

    /**
     * A member that is not one of the sorted members has no position, so no
     * record covers it, missing or present.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnIdOutsideTheMembersIsNeverCovered(): void
    {
        $stranger = '01932b4e-8a40-7000-8000-00000000000f';
        $result   = self::coverage([$stranger], [$stranger], [self::signed([0, 1, 2])]);

        self::assertSame([[Finding::MISSING_ENTRY, $stranger]], $result->findings);
        self::assertSame([], $result->recheck);
    }

    /**
     * Coverage reads nothing: it holds the signer alone, no connection and no
     * ledger, and answers here, where no application or database exists.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testItReadsNothing(): void
    {
        $properties = (new \ReflectionClass(PruneCoverage::class))->getProperties();

        self::assertCount(1, $properties);
        self::assertSame(SealSigner::class, (string) $properties[0]->getType());
        self::assertInstanceOf(PruneCoverageResult::class, self::coverage([self::FIRST], [], [self::golden('first')]));
    }

    /**
     * The coverage of the golden seal, its members sorted, with the missing and
     * present members, the membership and the records given.
     *
     * @param  list<string>  $missing
     * @param  list<string>  $present
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>  $records
     * @param  bool  $authentic
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneCoverageResult
     *
     * @throws \JsonException
     */
    private static function coverage(array $missing, array $present, array $records, bool $authentic = true): PruneCoverageResult
    {
        $seal = self::seal();

        self::assertSame(self::text('seal_digest'), $seal->digest());

        return (new PruneCoverage(self::signer()))->of($seal, $seal->digest(), [self::FIRST, self::SECOND, self::THIRD], $missing, $present, $authentic, $records);
    }

    /**
     * A record of the golden seal setting the positions, signed under the
     * golden key, with the bound fields given changed before it is signed.
     *
     * @param  list<int>  $positions
     * @param  array<string, int|string>  $changes
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \JsonException
     */
    private static function signed(array $positions, array $changes = []): PruneRecord
    {
        $fields = [
            'log_id'       => 'app-eu-1',
            'seal_id'      => self::SEAL_ID,
            'seal_digest'  => self::text('seal_digest'),
            'member_count' => 3,
            ...$changes,
        ];
        $members = (int) $fields['member_count'];

        return self::signer()->signPrune(
            (string) $fields['log_id'],
            (string) $fields['seal_id'],
            (string) $fields['seal_digest'],
            $members,
            PruneBitmap::encode($positions, $members),
            count($positions),
            self::OPERATION_ID,
            self::PRUNED_AT,
        );
    }

    /**
     * The record given with the fields given changed, its signature kept unless
     * one is given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @param  array<string, string>  $changes
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    private static function recordOf(PruneRecord $record, array $changes): PruneRecord
    {
        return PruneRecord::fromArray([...$record->toArray(), 'signature' => $record->signature, ...$changes]);
    }

    /**
     * The golden record named, under its golden signature.
     *
     * @param  'first'|'second'  $name
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \JsonException
     */
    private static function golden(string $name): PruneRecord
    {
        $fields = self::vectors()['prune_' . $name] ?? null;

        self::assertIsArray($fields);

        return PruneRecord::fromArray([...$fields, 'signature' => self::text('prune_' . $name . '_signature')]);
    }

    /**
     * The golden seal of three members, whose digest every coverage checks
     * against the golden one.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     *
     * @throws \JsonException
     */
    private static function seal(): SealEnvelope
    {
        return new SealEnvelope(
            'app-eu-1',
            self::SEAL_ID,
            1,
            null,
            null,
            3,
            self::text('members_digest'),
            '2026-10-31T23:34:56.000001Z',
            '2026-10-31T23:34:56.000003Z',
            '2026-10-31T23:40:00.000000Z',
            'k2026',
        );
    }

    /**
     * A signer whose one key is the golden key.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSigner
     *
     * @throws \JsonException
     */
    private static function signer(): SealSigner
    {
        $integrity = ['keys' => ['k2026' => self::text('secret')], 'current' => 'k2026'];

        return new SealSigner(new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity]]))));
    }

    /**
     * The golden string under the key given.
     *
     * @param  string  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function text(string $field): string
    {
        $value = self::vectors()[$field] ?? null;

        return is_string($value) ? $value : self::fail(sprintf('The golden prune vectors have no `%s`.', $field));
    }

    /**
     * The golden prune vectors, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function vectors(): array
    {
        $vectors = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);

        return is_array($vectors) ? $vectors : self::fail('The golden prune vectors are not a map.');
    }
}
