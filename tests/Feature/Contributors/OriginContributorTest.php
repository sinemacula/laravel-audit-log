<?php

declare(strict_types = 1);

namespace Tests\Feature\Contributors;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Tests\TestCase;

/**
 * Feature tests for the default contributor that says where the activity ran:
 * the innermost frame decides the origin and names the command or job, and
 * outside any frame the origin is console, with no name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OriginContributor::class)]
final class OriginContributorTest extends TestCase
{
    /**
     * An HTTP frame fills the origin, and no name: a request has none.
     *
     * @return void
     */
    public function testAnHttpFrameFillsHttp(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterRequest(Request::create('/'));

        $snapshot = self::contributed($frames);

        self::assertSame(Origin::HTTP, $snapshot->origin);
        self::assertNull($snapshot->context);
    }

    /**
     * A command frame fills console and the command's name.
     *
     * @return void
     */
    public function testACommandFrameFillsConsoleAndTheCommand(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterCommand(new \stdClass, 'invoices:send');

        $snapshot = self::contributed($frames);

        self::assertSame(Origin::CONSOLE, $snapshot->origin);
        self::assertSame(['command' => 'invoices:send'], $snapshot->context);
    }

    /**
     * A job frame fills queue and the job's name.
     *
     * @return void
     */
    public function testAJobFrameFillsQueueAndTheJob(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        $snapshot = self::contributed($frames);

        self::assertSame(Origin::QUEUE, $snapshot->origin);
        self::assertSame(['job' => 'App\Jobs\SendInvoice'], $snapshot->context);
    }

    /**
     * A job frame with no name fills queue and nothing in the context.
     *
     * @return void
     */
    public function testAJobWithNoNameFillsOnlyTheOrigin(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterJob(new \stdClass, null);

        $snapshot = self::contributed($frames);

        self::assertSame(Origin::QUEUE, $snapshot->origin);
        self::assertNull($snapshot->context);
    }

    /**
     * Outside any frame the origin is console, and there is no name.
     *
     * @return void
     */
    public function testNoFrameFillsConsoleAndNoName(): void
    {
        $snapshot = self::contributed(new ExecutionFrames);

        self::assertSame(Origin::CONSOLE, $snapshot->origin);
        self::assertNull($snapshot->context);
    }

    /**
     * A job inside a command inside a request is a job, named as the job, and
     * the frames beneath it add nothing.
     *
     * @return void
     */
    public function testTheInnermostFrameDecides(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterRequest(Request::create('/'));
        $frames->enterCommand(new \stdClass, 'invoices:send');
        $frames->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        $snapshot = self::contributed($frames);

        self::assertSame(Origin::QUEUE, $snapshot->origin);
        self::assertSame(['job' => 'App\Jobs\SendInvoice'], $snapshot->context);
    }

    /**
     * An origin already filled is kept, as the first to fill a field wins.
     *
     * @return void
     */
    public function testAFilledOriginIsKept(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterRequest(Request::create('/'));

        $pending = (new PendingRecord)->event('invoice.approved');

        $pending->fillOrigin(Origin::QUEUE);

        (new OriginContributor($frames))->contribute(new Contribution($pending));

        self::assertSame(Origin::QUEUE, $pending->snapshot()->origin);
    }

    /**
     * What the contributor fills into a fresh builder, under the frames.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames  $frames
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private static function contributed(ExecutionFrames $frames): PendingSnapshot
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        (new OriginContributor($frames))->contribute(new Contribution($pending));

        return $pending->snapshot();
    }
}
