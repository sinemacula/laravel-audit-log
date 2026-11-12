<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTally;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the running count of a prune.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneTally::class)]
final class PruneTallyTest extends TestCase
{
    /** @var string The run every tally counts. */
    private const string RUN = '01932b4e-c000-7000-8000-000000000001';

    /** @var string The first seal a chunk deletes from. */
    private const string SEAL = '01932b4e-a000-7000-8000-000000000001';

    /** @var string The second seal a chunk deletes from. */
    private const string OTHER_SEAL = '01932b4e-a000-7000-8000-000000000002';

    /** @var string The run's midnight. */
    private const string MIDNIGHT = '2026-11-04 15:00:00';

    /**
     * An empty tally is complete, deletes nothing and plans only on a dry run.
     *
     * @return void
     */
    public function testANewTallyIsCompleteAndCountsNothing(): void
    {
        $tally = new PruneTally(self::RUN, false);

        $tally->start('config:0123456789abcdef', 2, 5);

        $result = $tally->result();

        self::assertSame(PruneStatus::COMPLETE, $tally->status());
        self::assertSame(
            [self::RUN, true, false, null, 'config:0123456789abcdef', 0, 0, 0, 0, 0, 2, 3, [], 0, [], null],
            [
                $result->operationId, $result->committed, $result->dryRun, $result->failure, $result->policyVersion, $result->deleted, $result->seals,
                $result->held, $result->pendingDelivery, $result->skippedSeals, $result->cursor, $result->remaining, $result->categories,
                $result->tenantsAffected, $result->skippedSealIds, $result->plan,
            ],
        );
        self::assertTrue($tally->hasStarted());
    }

    /**
     * Only a started run owes its finish row, and a dry run never starts.
     *
     * @return void
     */
    public function testOnlyARunThatStartedOwesItsFinish(): void
    {
        $run = new PruneTally(self::RUN, false);
        $dry = new PruneTally(self::RUN, true);

        $run->underPolicy('config:0123456789abcdef');
        $dry->start('config:0123456789abcdef', 0, 3);

        self::assertFalse($run->hasStarted());
        self::assertFalse($run->result()->committed);
        self::assertSame('config:0123456789abcdef', $run->result()->policyVersion);
        self::assertFalse($dry->hasStarted());
        self::assertFalse($dry->result()->committed);
        self::assertTrue($dry->result()->dryRun);
    }

    /**
     * Committed chunks are counted by seal, category and tenant.
     *
     * @return void
     */
    public function testCommittedChunksAreCountedBySealCategoryAndTenant(): void
    {
        $tally = new PruneTally(self::RUN, false);
        $rows  = [
            'a' => ['category' => 'finance', 'tenant_type' => 'organisation', 'tenant_id' => 'org_01'],
            'b' => ['category' => 'finance', 'tenant_type' => 'organisation', 'tenant_id' => 'org_02'],
            'c' => ['category' => 'security', 'tenant_type' => 'organisation', 'tenant_id' => 'org_01'],
            'd' => ['category' => 'security', 'tenant_type' => null, 'tenant_id' => null],
        ];

        $tally->committed(self::SEAL, self::outcome(['a', 'b'], 1, 0), $rows);
        $tally->committed(self::SEAL, self::outcome(['c'], 0, 2), $rows);
        $tally->committed(self::OTHER_SEAL, self::outcome([], 3, 0), $rows);
        $tally->committed(self::OTHER_SEAL, self::outcome(['d'], 0, 0), $rows);

        $result = $tally->result();

        self::assertSame([4, 2, 4, 2, 2], [$result->deleted, $result->seals, $result->held, $result->pendingDelivery, $result->tenantsAffected]);
        self::assertSame(['finance' => 2, 'security' => 2], $result->categories);
        self::assertSame(PruneStatus::PARTIAL, $result->status);
    }

    /**
     * Rows of `[what happens, the status]`: left work is partial.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Lifecycle\PruneTally): void, 1: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus}>
     */
    public static function provideStatuses(): iterable
    {
        yield from [
            'nothing left'          => [static function (PruneTally $tally): void {}, PruneStatus::COMPLETE],
            'a held entry'          => [static fn (PruneTally $tally) => $tally->committed(self::SEAL, self::outcome([], 1, 0), []), PruneStatus::PARTIAL],
            'a pending delivery'    => [static fn (PruneTally $tally) => $tally->committed(self::SEAL, self::outcome([], 0, 1), []), PruneStatus::PARTIAL],
            'a skipped seal'        => [static fn (PruneTally $tally) => $tally->skipped(self::SEAL), PruneStatus::PARTIAL],
            'the budget stopped it' => [static fn (PruneTally $tally) => $tally->stop(), PruneStatus::PARTIAL],
            'a failure'             => [static fn (PruneTally $tally) => $tally->fail('prune_failed'), PruneStatus::FAILED],
            'a failure and a stop'  => [static function (PruneTally $tally): void {
                $tally->stop();
                $tally->fail('journal_broken');
            }, PruneStatus::FAILED],
        ];
    }

    /**
     * The status follows what happened to the run.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Lifecycle\PruneTally): void  $happens
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus  $status
     * @return void
     */
    #[DataProvider('provideStatuses')]
    public function testTheStatusFollowsWhatHappened(\Closure $happens, PruneStatus $status): void
    {
        $tally = new PruneTally(self::RUN, false);

        $happens($tally);

        self::assertSame($status, $tally->status());
        self::assertSame($status, $tally->result()->status);
    }

    /**
     * The first failure is the run's reason, and a later one never replaces it.
     *
     * @return void
     */
    public function testTheFirstFailureIsTheReason(): void
    {
        $tally = new PruneTally(self::RUN, false);

        $tally->fail('configuration_refused');
        $tally->fail('prune_failed');

        self::assertSame('configuration_refused', $tally->result()->failure);
    }

    /**
     * Every skipped seal is counted and the first hundred named.
     *
     * @return void
     */
    public function testSkippedSealsAreCountedAndTheFirstHundredNamed(): void
    {
        $tally = new PruneTally(self::RUN, false);

        $tally->skipped(null);

        for ($index = 1; $index <= 120; $index++) {
            $tally->skipped(sprintf('01932b4e-a000-7000-8000-%012d', $index));
        }

        $result = $tally->result();

        self::assertSame(121, $result->skippedSeals);
        self::assertCount(100, $result->skippedSealIds);
        self::assertSame('01932b4e-a000-7000-8000-000000000001', $result->skippedSealIds[0]);
        self::assertSame('01932b4e-a000-7000-8000-000000000100', $result->skippedSealIds[99]);
    }

    /**
     * The cursor follows the last seal; what is left never goes below none.
     *
     * @return void
     */
    public function testTheCursorAndWhatIsLeft(): void
    {
        $tally = new PruneTally(self::RUN, false);

        $tally->start('config:0123456789abcdef', 0, 4);
        $tally->walked(1);
        $tally->walked(2);

        self::assertSame([2, 2], [$tally->result()->cursor, $tally->result()->remaining]);

        $tally->walked(4);

        self::assertSame([4, 0], [$tally->result()->cursor, $tally->result()->remaining]);

        $tally->walked(6);

        self::assertSame(0, $tally->result()->remaining);
    }

    /**
     * The budget ends the given seconds after the start, unless unlimited.
     *
     * @return void
     */
    public function testTheBudgetEndsTheGivenSecondsAfterTheStart(): void
    {
        $tally = new PruneTally(self::RUN, false);

        self::assertFalse($tally->isPastBudget(PHP_INT_MAX - 1));
        self::assertSame(1, $tally->batch());

        $tally->limit(250, 60, 1000);

        self::assertFalse($tally->isPastBudget(1059));
        self::assertTrue($tally->isPastBudget(1060));
        self::assertTrue($tally->isPastBudget(1061));
        self::assertSame(250, $tally->batch());
    }

    /**
     * A dry run plans each eligible entry under its pair and its seal.
     *
     * @return void
     */
    public function testADryRunPlansPerPairAndPerSeal(): void
    {
        $decisions = self::decisions();
        $tally     = new PruneTally(self::RUN, true);
        $tenant    = Reference::of('organisation', 'org_01');

        $tally->planned(1, $decisions->for('security', $tenant), false);
        $tally->planned(1, $decisions->for('finance', null), false);
        $tally->planned(2, $decisions->for('security', $tenant), false);
        $tally->planned(2, $decisions->for('audit', null), true);

        $result = $tally->result();

        self::assertSame([
            'pairs' => [
                ['category' => 'security', 'tenant_type' => 'organisation', 'tenant_id' => 'org_01', 'cutoff' => '2026-11-03T00:00:00.000000Z', 'eligible' => 2],
                ['category' => 'finance', 'tenant_type' => null, 'tenant_id' => null, 'cutoff' => '2026-10-05T00:00:00.000000Z', 'eligible' => 1],
                ['category' => 'audit', 'tenant_type' => null, 'tenant_id' => null, 'cutoff' => '2026-10-05T00:00:00.000000Z', 'eligible' => 0],
            ],
            'seals' => [1 => 2, 2 => 1],
        ], $result->plan);
        self::assertSame(1, $result->held);
        self::assertSame(0, $result->deleted);
        self::assertSame(PruneStatus::PARTIAL, $result->status);
    }

    /**
     * The finish row carries the run, its bounded categories and its decisions.
     *
     * @return void
     */
    public function testTheFinishPayloadCarriesTheRunAndItsDecisions(): void
    {
        $decisions = self::decisions();
        $tally     = new PruneTally(self::RUN, false);

        $decisions->for('security', Reference::of('organisation', 'org_01'));
        $decisions->for('finance', null);
        $decisions->for('security', Reference::of('organisation', 'org_02'));

        $tally->start('config:0123456789abcdef', 0, 3);
        $tally->committed(self::SEAL, self::outcome(['a'], 0, 0), ['a' => ['category' => 'finance', 'tenant_type' => null, 'tenant_id' => null]]);
        $tally->walked(3);

        $every = array_map(static fn ($decision): array => $decision->toArray(), $decisions->all());

        self::assertSame([
            'run_id'           => self::RUN,
            'phase'            => 'finish',
            'status'           => 'complete',
            'failure'          => null,
            'deleted'          => 1,
            'seals'            => 1,
            'held'             => 0,
            'pending_delivery' => 0,
            'skipped_seals'    => 0,
            'cursor'           => 3,
            'remaining'        => 0,
            'categories'       => ['finance' => 1],
            'tenants_affected' => 0,
            'pairs'            => 3,
            'decisions'        => [
                ['finance', 30, null, '2026-10-05T00:00:00.000000Z', 1],
                ['security', 1, null, '2026-11-03T00:00:00.000000Z', 2],
            ],
            'decisions_omitted' => 0,
            'decisions_digest'  => hash('sha256', CanonicalEncoder::encode($every)),
        ], $tally->finishPayload($decisions));
    }

    /**
     * The finish row stays bounded however many tenants there are.
     *
     * @return void
     */
    public function testTheFinishPayloadIsBoundedWhateverTheDecisions(): void
    {
        $decisions = self::decisions();

        for ($index = 1; $index <= 1000; $index++) {
            $decisions->for('security', Reference::of('organisation', 'org_' . $index));
        }

        $payload = (new PruneTally(self::RUN, false))->finishPayload($decisions);

        self::assertSame([['security', 1, null, '2026-11-03T00:00:00.000000Z', 1000]], $payload['decisions']);
        self::assertSame([1000, 0], [$payload['pairs'], $payload['decisions_omitted']]);

        $many = self::decisions();

        for ($index = 1; $index <= 1005; $index++) {
            $many->for(sprintf('category_%04d', $index), null);
        }

        $payload = (new PruneTally(self::RUN, false))->finishPayload($many);

        self::assertIsArray($payload['decisions']);
        self::assertCount(1000, $payload['decisions']);
        self::assertSame(['category_0001', 30, null, '2026-10-05T00:00:00.000000Z', 1], $payload['decisions'][0]);
        self::assertSame(['category_1000', 30, null, '2026-10-05T00:00:00.000000Z', 1], $payload['decisions'][999]);
        self::assertSame(5, $payload['decisions_omitted']);
    }

    /**
     * The progress names the run, status, deletions and cursor.
     *
     * @return void
     */
    public function testTheProgressNamesTheRun(): void
    {
        $tally = new PruneTally(self::RUN, false);

        $tally->start('config:0123456789abcdef', 0, 2);
        $tally->committed(self::SEAL, self::outcome(['a', 'b'], 0, 0), []);
        $tally->walked(2);

        self::assertSame(
            ['at' => '2026-11-04T15:00:00.000000Z', 'run_id' => self::RUN, 'status' => 'complete', 'deleted' => 2, 'cursor' => 2],
            $tally->progress('2026-11-04T15:00:00.000000Z'),
        );
    }

    /**
     * The outcome of a committed chunk that deleted the ids given.
     *
     * @param  list<string>  $deleted
     * @param  int  $held
     * @param  int  $pending
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome
     */
    private static function outcome(array $deleted, int $held, int $pending): PruneChunkOutcome
    {
        $integrity = ['keys' => ['k2026' => 'audit-log golden key 0123456789!'], 'current' => 'k2026'];
        $replay    = JournalReplay::start(new JournalSigner(new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity]])))), 'app-eu-1');

        return new PruneChunkOutcome($deleted, $held, $pending, 0, false, $replay);
    }

    /**
     * Decisions at the test's midnight: `security` kept a day, the rest thirty.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions
     */
    private static function decisions(): RetentionDecisions
    {
        $policy = new class implements RetentionPolicy {
            /**
             * The policy's version.
             *
             * @return string
             */
            #[\Override]
            public function version(): string
            {
                return 'test:1';
            }

            /**
             * A day for `security`, thirty days for anything else.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return int
             */
            #[\Override]
            public function retainFor(string $category, ?Reference $tenant): int
            {
                return $category === 'security' ? 1 : 30;
            }

            /**
             * No preservation.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return ?int
             */
            #[\Override]
            public function preserveFor(string $category, ?Reference $tenant): ?int
            {
                return null;
            }
        };

        return new RetentionDecisions($policy, new \DateTimeImmutable(self::MIDNIGHT, new \DateTimeZone('UTC')));
    }
}
