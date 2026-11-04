<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome;

/**
 * Unit tests for what one prune chunk did: the ids it deleted and the counts it
 * kept, as given, with the replay it ended with; and the outcome of a chunk a
 * candidate of which failed verification, which deleted nothing and skips its
 * seal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneChunkOutcome::class)]
final class PruneChunkOutcomeTest extends TestCase
{
    /**
     * An outcome keeps the deleted ids, each count and the replay as given.
     *
     * @return void
     */
    public function testItKeepsWhatTheChunkDid(): void
    {
        $replay  = self::replay();
        $outcome = new PruneChunkOutcome(['01932b4e-9000-7000-8000-000000000001'], 2, 3, 4, false, $replay);

        self::assertSame(['01932b4e-9000-7000-8000-000000000001'], $outcome->deleted);
        self::assertSame([2, 3, 4, false], [$outcome->held, $outcome->pendingDelivery, $outcome->ineligible, $outcome->sealFailed]);
        self::assertSame($replay, $outcome->replay);
    }

    /**
     * A chunk a candidate of which failed verification deleted nothing, kept
     * nothing it counted, and skips its seal, with the replay it ended with.
     *
     * @return void
     */
    public function testAFailedSealDeletesNothingAndIsSkipped(): void
    {
        $replay  = self::replay();
        $outcome = PruneChunkOutcome::skippingTheSeal($replay);

        self::assertSame([], $outcome->deleted);
        self::assertSame([0, 0, 0, true], [$outcome->held, $outcome->pendingDelivery, $outcome->ineligible, $outcome->sealFailed]);
        self::assertSame($replay, $outcome->replay);
    }

    /**
     * A replay of nothing yet.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private static function replay(): JournalReplay
    {
        $integrity = ['keys' => ['k2026' => 'audit-log golden key 0123456789!'], 'current' => 'k2026'];

        return JournalReplay::start(new JournalSigner(new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity]])))), 'app-eu-1');
    }
}
