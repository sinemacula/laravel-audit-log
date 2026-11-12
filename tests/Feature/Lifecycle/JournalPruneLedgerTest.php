<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for the prune ledger read from the lifecycle journal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalPruneLedger::class)]
final class JournalPruneLedgerTest extends TestCase
{
    use WritesTheJournal;

    /** @var string The seal the tests prune. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string Another seal. */
    private const string OTHER_SEAL_ID = '01932b4e-9000-7000-8000-000000000002';

    /** @var string The digest every pruned seal is given. */
    private const string SEAL_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string The id of the prune run every prune row names. */
    private const string RUN_ID = '01932b4e-b000-7000-8000-000000000001';

    /** @var string The refusal of a row of the seal with no record that can be read. */
    private const string UNREADABLE = 'The lifecycle journal holds a prune row of the seal `01932b4e-9000-7000-8000-000000000001` with no record that can be read.';

    /**
     * Every record of the seal is read in journal order, each as it was signed.
     *
     * @return void
     */
    public function testItReturnsEveryRecordOfTheSealInOrder(): void
    {
        $first  = self::record(self::SEAL_ID, [0, 2], '01932b4e-a000-7000-8000-000000000001');
        $other  = self::record(self::OTHER_SEAL_ID, [1], '01932b4e-a000-7000-8000-000000000002');
        $second = self::record(self::SEAL_ID, [1], '01932b4e-a000-7000-8000-000000000003');
        $third  = self::record(self::SEAL_ID, [3], '01932b4e-a000-7000-8000-000000000004');

        foreach ([$first, $other, $second, $third] as $record) {
            $this->journalPrune($record);
        }

        $ledger = new JournalPruneLedger(app(DatabaseManager::class));

        self::assertInstanceOf(PruneLedger::class, $ledger);
        self::assertEquals([$first, $second, $third], $ledger->recordsFor(self::SEAL_ID));
        self::assertEquals([$other], $ledger->recordsFor(self::OTHER_SEAL_ID));
        $operations = array_map(static fn (PruneRecord $record): string => $record->operationId, $ledger->recordsFor(self::SEAL_ID));

        self::assertSame(['01932b4e-a000-7000-8000-000000000001', '01932b4e-a000-7000-8000-000000000003', '01932b4e-a000-7000-8000-000000000004'], $operations);
    }

    /**
     * Only the seal's own `prune` rows count.
     *
     * @return void
     */
    public function testItIgnoresOtherKindsAndSeals(): void
    {
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => self::RUN_ID, 'phase' => 'start']);
        $this->journalPrune(self::record(self::OTHER_SEAL_ID, [0], '01932b4e-a000-7000-8000-000000000001'));
        $record = self::stored(self::record(self::SEAL_ID, [0], '01932b4e-a000-7000-8000-000000000002'));

        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0123456789abcdef', 'record' => $record]);

        $ledger = new JournalPruneLedger(app(DatabaseManager::class));

        self::assertSame([], $ledger->recordsFor(self::SEAL_ID));
        self::assertCount(1, $ledger->recordsFor(self::OTHER_SEAL_ID));
        self::assertSame([], $ledger->recordsFor('01932b4e-9000-7000-8000-00000000ffff'));
    }

    /**
     * Rows of `[the payload stored, the message]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideMalformedPayloads(): iterable
    {
        yield from [
            'not json'            => ['{"record":', self::UNREADABLE],
            'too deep'            => [str_repeat('[', 65) . str_repeat(']', 65), self::UNREADABLE],
            'a list'              => ['[1, 2]', self::UNREADABLE],
            'no record'           => ['{"run_id":"' . self::RUN_ID . '"}', self::UNREADABLE],
            'a record of text'    => ['{"record":"BQ"}', self::UNREADABLE],
            'a record of v1'      => ['{"record":{"v":1}}', 'A stored prune record must be of version 2.'],
            'a record with a gap' => ['{"record":{"v":2,"log_id":"app"}}', 'A stored prune record\'s `seal_id` must be text.'],
        ];
    }

    /**
     * A prune row whose payload holds no readable record is refused.
     *
     * @param  string  $payload
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedPayloads')]
    public function testAMalformedPayloadIsRefusedNamingTheSeal(string $payload, string $message): void
    {
        $this->journalPrune(self::record(self::SEAL_ID, [0], '01932b4e-a000-7000-8000-000000000001'));
        $this->tamperJournal(1, ['payload' => $payload]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        (new JournalPruneLedger(app(DatabaseManager::class)))->recordsFor(self::SEAL_ID);
    }

    /**
     * Records are read on the storage writer, so verification needs no
     * credentials that can delete.
     *
     * @return void
     */
    public function testItReadsTheStorageConnectionsWriter(): void
    {
        $record = self::record(self::SEAL_ID, [0], '01932b4e-a000-7000-8000-000000000001');

        $this->journalPrune($record);

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', 'nowhere');

        $connection = DB::connection(StorageConnection::name());
        $reads      = [];

        $connection->listen(static function (QueryExecuted $query) use (&$reads): void {
            $reads[] = $query->sql;
        });

        $connection->setReadPdo(static function (): never {
            throw new \LogicException('The reader is never asked.');
        });

        try {
            self::assertEquals([$record], (new JournalPruneLedger(app(DatabaseManager::class)))->recordsFor(self::SEAL_ID));
        } finally {
            $connection->setReadPdo(null);
        }

        self::assertCount(1, $reads);
        self::assertStringContainsString(LifecycleTables::journalTable(), $reads[0]);
    }

    /**
     * Append a `prune` row holding the record, as the pruner writes one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return void
     */
    private function journalPrune(PruneRecord $record): void
    {
        $this->journalRow(JournalKind::PRUNE, ['record' => self::stored($record), 'run_id' => self::RUN_ID], sealId: $record->sealId);
    }

    /**
     * A record of the seal, of four members, signed under the ring's signing
     * key.
     *
     * @param  string  $sealId
     * @param  list<int>  $positions
     * @param  string  $operationId
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    private static function record(string $sealId, array $positions, string $operationId): PruneRecord
    {
        return app(SealSigner::class)->signPrune(
            'app-eu-1',
            $sealId,
            self::SEAL_DIGEST,
            4,
            PruneBitmap::encode($positions, 4),
            count($positions),
            $operationId,
            '2027-11-01T00:00:00.000000Z',
        );
    }

    /**
     * The record as a prune row's payload holds it: its fields and its
     * signature.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return array<string, int|string>
     */
    private static function stored(PruneRecord $record): array
    {
        return [...$record->toArray(), 'signature' => $record->signature];
    }
}
