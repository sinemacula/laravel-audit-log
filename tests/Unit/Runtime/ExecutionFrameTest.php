<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrame;

/**
 * Unit tests for one execution frame: what each kind keeps, and that an empty
 * name is no name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExecutionFrame::class)]
final class ExecutionFrameTest extends TestCase
{
    /**
     * A request's frame is owned by the request, keeps it and has no name.
     *
     * @return void
     */
    public function testAFrameOfARequestOwnsTheRequest(): void
    {
        $request = Request::create('/invoices');

        $frame = ExecutionFrame::request($request);

        self::assertSame(FrameKind::HTTP, $frame->kind);
        self::assertSame($request, $frame->owner);
        self::assertSame($request, $frame->request);
        self::assertNull($frame->name);
    }

    /**
     * A command's frame is owned by its input, keeps its name and has no
     * request.
     *
     * @return void
     */
    public function testACommandFrameKeepsItsName(): void
    {
        $input = new \stdClass;

        $frame = ExecutionFrame::command($input, 'invoices:send');

        self::assertSame(FrameKind::COMMAND, $frame->kind);
        self::assertSame($input, $frame->owner);
        self::assertSame('invoices:send', $frame->name);
        self::assertNull($frame->request);
    }

    /**
     * A job's frame is owned by the job, keeps its name and has no request.
     *
     * @return void
     */
    public function testAJobFrameKeepsItsName(): void
    {
        $job = new \stdClass;

        $frame = ExecutionFrame::job($job, 'App\Jobs\SendInvoice');

        self::assertSame(FrameKind::JOB, $frame->kind);
        self::assertSame($job, $frame->owner);
        self::assertSame('App\Jobs\SendInvoice', $frame->name);
        self::assertNull($frame->request);
    }

    /**
     * An empty name is none, which is what the framework's empty command name
     * must become, so nothing downstream records an empty name.
     *
     * @return void
     */
    public function testAnEmptyNameIsNone(): void
    {
        self::assertNull(ExecutionFrame::command(new \stdClass, '')->name);
        self::assertNull(ExecutionFrame::job(new \stdClass, '')->name);
    }

    /**
     * A job with no name has none.
     *
     * @return void
     */
    public function testAJobMayHaveNoName(): void
    {
        self::assertNull(ExecutionFrame::job(new \stdClass, null)->name);
    }

    /**
     * A name that reads as false to a loose check is still a name, which
     * protects against a mutation that swaps the empty check for a truthy one.
     *
     * @return void
     */
    public function testANameOfZeroIsKept(): void
    {
        self::assertSame('0', ExecutionFrame::command(new \stdClass, '0')->name);
    }

    /**
     * A job's frame keeps the actor it carried and the users left on the
     * guards, and a job given neither has neither.
     *
     * @return void
     */
    public function testAJobFrameKeepsWhatItStartedWith(): void
    {
        $carried = new ActorSnapshot(Reference::of('user', 'user-7'), 'web');
        $user    = new \stdClass;
        $frame   = ExecutionFrame::job(new \stdClass, 'App\Jobs\SendInvoice', $carried, ['web' => $user]);

        self::assertSame($carried, $frame->carried);
        self::assertSame(['web' => $user], $frame->leftovers);

        $bare = ExecutionFrame::job(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertNull($bare->carried);
        self::assertSame([], $bare->leftovers);
    }
}
