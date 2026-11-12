<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeals;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Feature tests for the seals a prune walks and their present members.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneSeals::class)]
#[CoversClass(PruneSeal::class)]
final class PruneSealsTest extends TestCase
{
    use SealsEntries;

    /** @var string When every seal is made. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var list<string> Entry ids out of bytewise order: a letter sorts after every digit. */
    private const array IDS = [
        '01932b4e-9000-7000-8000-0000000000b1',
        '01932b4e-9000-7000-8000-000000000021',
        '01932b4e-9000-7000-8000-0000000000a1',
        '01932b4e-9000-7000-8000-000000000011',
    ];

    /**
     * Seal the entries given, out of order, at the test's time.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);

        foreach (self::IDS as $index => $id) {
            $this->storeEntryAt(sprintf('2026-11-01 12:00:00.%06d', $index + 1), $id);
        }

        $this->sealAll();
    }

    /**
     * An authentic seal loads with its stored envelope, digest and member
     * HMACs.
     *
     * @return void
     */
    public function testAnAuthenticSealLoads(): void
    {
        $stored = $this->seals()[0];
        $seal   = $this->loadSeal(1);

        self::assertInstanceOf(PruneSeal::class, $seal);
        self::assertSame($stored['id'], $seal->envelope->id);
        self::assertSame($stored['seal_digest'], $seal->digest);
        self::assertSame(4, $seal->envelope->memberCount);

        $members = $this->maintenance()->table(IntegrityTables::membersTable())->pluck('hmac', 'entry_id')->all();

        foreach ($members as $id => $hmac) {
            self::assertSame($hmac, $seal->memberHmac((string) $id));
        }
    }

    /**
     * A sequence with no seal loads nothing.
     *
     * @return void
     */
    public function testAMissingSealLoadsNothing(): void
    {
        self::assertNull($this->loadSeal(2));
    }

    /**
     * Rows of `[what the test does to the stored seal]`.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Feature\Lifecycle\PruneSealsTest): void}>
     */
    public static function provideAuthenticationFailures(): iterable
    {
        yield from [
            'a stored digest'       => [static fn (self $test) => $test->changeSeal(['seal_digest' => str_repeat('e', 64)])],
            'a signature'           => [static fn (self $test) => $test->changeSeal(['signature' => str_repeat('e', 64)])],
            'a malformed signature' => [static fn (self $test) => $test->changeSeal(['signature' => 'not a signature'])],
            'a log id'              => [static fn (self $test) => app(ConfigRepository::class)->set('audit-log.integrity.log_id', 'another-log')],
            'a member count'        => [static fn (self $test) => $test->dropAMember()],
            'a members digest'      => [static fn (self $test) => $test->changeAMembersHmac()],
            'an unknown key'        => [static fn (self $test) => $test->rekeySeal('k1999')],
            'an algorithm version'  => [static fn (self $test) => $test->changeSeal(['algorithm_version' => 9])],
            'a signer'              => [static fn (self $test) => $test->changeSeal(['signer' => 'other'])],
            'a malformed column'    => [static fn (self $test) => $test->changeSeal(['members_digest' => 'not a digest'])],
        ];
    }

    /**
     * A seal that fails authentication loads nothing, so it is never pruned.
     *
     * @param  \Closure(\Tests\Feature\Lifecycle\PruneSealsTest): void  $tamper
     * @return void
     */
    #[DataProvider('provideAuthenticationFailures')]
    public function testEachAuthenticationFailureGivesNull(\Closure $tamper): void
    {
        self::assertInstanceOf(PruneSeal::class, $this->loadSeal(1));

        $tamper($this);

        self::assertNull($this->loadSeal(1));
    }

    /**
     * The members are sorted bytewise by entry id in PHP, whatever order the
     * engine returns.
     *
     * @return void
     */
    public function testMembersAreSortedBytewise(): void
    {
        $seal   = $this->loadSeal(1);
        $sorted = self::IDS;

        usort($sorted, strcmp(...));

        self::assertInstanceOf(PruneSeal::class, $seal);
        self::assertSame($sorted, $seal->memberIds);
        self::assertSame(0, $seal->positionOf('01932b4e-9000-7000-8000-000000000011'));
        self::assertSame(3, $seal->positionOf('01932b4e-9000-7000-8000-0000000000b1'));
    }

    /**
     * The present members are read in one statement, sorted bytewise.
     *
     * @return void
     */
    public function testPresentReadsOneStatement(): void
    {
        $seal = $this->loadSeal(1);

        self::assertInstanceOf(PruneSeal::class, $seal);

        $this->maintenance()->table(EntrySettings::table())->where('id', self::IDS[2])->delete();

        $statements = 0;

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements++;
        });

        $present = app(PruneSeals::class)->present($this->maintenance(), $seal);

        self::assertSame(1, $statements);
        self::assertSame(['01932b4e-9000-7000-8000-000000000011', '01932b4e-9000-7000-8000-000000000021', '01932b4e-9000-7000-8000-0000000000b1'], array_column($present, 'id'));
        self::assertSame(PruneSeals::PRESENT_COLUMNS, array_keys($present[0]));
        self::assertSame(['finance', 'organisation', 'org_01', 'user', '42', 'invoice', 'inv_0042', null, 'invoice.approved'], [
            $present[0]['category'],
            $present[0]['tenant_type'],
            $present[0]['tenant_id'],
            $present[0]['actor_type'],
            $present[0]['actor_id'],
            $present[0]['subject_type'],
            $present[0]['subject_id'],
            $present[0]['import_batch_id'],
            $present[0]['event'],
        ]);
    }

    /**
     * Change the stored seal's columns, as raw values.
     *
     * @param  array<string, int|string>  $columns
     * @return void
     */
    public function changeSeal(array $columns): void
    {
        $this->maintenance()->table(IntegrityTables::checkpointsTable())->where('sequence', 1)->update($columns);
    }

    /**
     * Name another key on the stored seal, so the seal fails on its key alone.
     *
     * @param  string  $keyId
     * @return void
     */
    public function rekeySeal(string $keyId): void
    {
        $this->changeSeal(['key_id' => $keyId]);
        $this->changeSeal(['seal_digest' => SealEnvelope::fromRow($this->seals()[0])->digest()]);
    }

    /**
     * Delete one of the seal's member rows.
     *
     * @return void
     */
    public function dropAMember(): void
    {
        $this->maintenance()->table(IntegrityTables::membersTable())->where('entry_id', self::IDS[0])->delete();
    }

    /**
     * Change one member's sealed HMAC.
     *
     * @return void
     */
    public function changeAMembersHmac(): void
    {
        $this->maintenance()->table(IntegrityTables::membersTable())->where('entry_id', self::IDS[0])->update(['hmac' => str_repeat('e', 64)]);
    }

    /**
     * The authenticated seal at the sequence, or `null`.
     *
     * @param  int  $sequence
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal
     */
    private function loadSeal(int $sequence): ?PruneSeal
    {
        return app(PruneSeals::class)->load($this->maintenance(), $sequence);
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
