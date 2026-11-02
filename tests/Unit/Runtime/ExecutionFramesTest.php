<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrame;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;

/**
 * Unit tests for the stack of execution frames: the origin and request outside
 * any frame, the innermost frame deciding, leaving by the owner's identity, a
 * request replacing the stack and never being popped, and the two questions
 * that look beneath the innermost frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExecutionFrames::class)]
#[CoversClass(ExecutionFrame::class)]
final class ExecutionFramesTest extends TestCase
{
    /**
     * Outside any frame the origin is console, which covers a provider's
     * `boot()` and a test body.
     *
     * @return void
     */
    public function testOutsideAnyFrameTheOriginIsConsole(): void
    {
        $frames = new ExecutionFrames;

        self::assertSame(Origin::CONSOLE, $frames->origin());
        self::assertNull($frames->current());
    }

    /**
     * Outside any frame there is no request of either kind and no job.
     *
     * @return void
     */
    public function testOutsideAnyFrameThereIsNoRequest(): void
    {
        $frames = new ExecutionFrames;

        self::assertNull($frames->request());
        self::assertNull($frames->inboundRequest());
        self::assertNull($frames->carriedActor());
    }

    /**
     * Rows of `[what to enter, kind, origin]`: each kind of frame.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames): void, 1: \SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind, 2: \SineMacula\Laravel\AuditLog\Records\Enums\Origin}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideFrames(): iterable
    {
        yield from [
            'a request' => [static fn (ExecutionFrames $frames) => $frames->enterRequest(Request::create('/')), FrameKind::HTTP, Origin::HTTP],
            'a command' => [static fn (ExecutionFrames $frames) => $frames->enterCommand(new \stdClass, 'invoices:send'), FrameKind::COMMAND, Origin::CONSOLE],
            'a job'     => [static fn (ExecutionFrames $frames) => $frames->enterJob(new \stdClass, 'App\Jobs\SendInvoice'), FrameKind::JOB, Origin::QUEUE],
        ];
    }

    /**
     * Each frame, alone on the stack, is the current one and gives its origin.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames): void  $enter
     * @param  \SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind  $kind
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Origin  $origin
     * @return void
     */
    #[DataProvider('provideFrames')]
    public function testEachFrameDecidesTheOrigin(\Closure $enter, FrameKind $kind, Origin $origin): void
    {
        $frames = new ExecutionFrames;

        $enter($frames);

        self::assertSame($kind, $frames->current()?->kind);
        self::assertSame($origin, $frames->origin());
    }

    /**
     * The innermost frame decides the origin and the current frame at every
     * depth.
     *
     * @return void
     */
    public function testTheInnermostFrameDecides(): void
    {
        $frames  = new ExecutionFrames;
        $command = new \stdClass;
        $job     = new \stdClass;

        $frames->enterRequest(Request::create('/'));
        $frames->enterCommand($command, 'invoices:send');
        self::assertSame(Origin::CONSOLE, $frames->origin());
        self::assertSame('invoices:send', $frames->current()?->name);

        $frames->enterJob($job, 'App\Jobs\SendInvoice');
        self::assertSame(Origin::QUEUE, $frames->origin());
        self::assertSame('App\Jobs\SendInvoice', $frames->current()?->name);
    }

    /**
     * Leaving a frame brings back the one beneath it, all the way down to the
     * request, and to no frame at all without one.
     *
     * @return void
     */
    public function testLeavingRestoresThePreviousFrame(): void
    {
        $frames  = new ExecutionFrames;
        $outer   = new \stdClass;
        $inner   = new \stdClass;
        $request = Request::create('/');

        $frames->enterRequest($request);
        $frames->enterCommand($outer, 'invoices:send');
        $frames->enterJob($inner, 'App\Jobs\SendInvoice');

        $frames->leave($inner);
        self::assertSame($outer, $frames->current()?->owner);
        self::assertSame(Origin::CONSOLE, $frames->origin());

        $frames->leave($outer);
        self::assertSame($request, $frames->current()?->owner);
        self::assertSame(Origin::HTTP, $frames->origin());
        self::assertSame($request, $frames->request());
    }

    /**
     * The last frame of a stack with no request leaves no frame at all, which
     * protects against a mutation that stops the search above the first index.
     *
     * @return void
     */
    public function testLeavingTheOnlyFrameLeavesNone(): void
    {
        $frames = new ExecutionFrames;
        $job    = new \stdClass;

        $frames->enterJob($job, 'App\Jobs\SendInvoice');
        $frames->leave($job);

        self::assertNull($frames->current());
        self::assertSame(Origin::CONSOLE, $frames->origin());
    }

    /**
     * Leaving a job twice leaves the frame beneath it in place, since a failed
     * job fires two ending events.
     *
     * @return void
     */
    public function testLeavingAJobTwiceIsHarmless(): void
    {
        $frames  = new ExecutionFrames;
        $command = new \stdClass;
        $job     = new \stdClass;

        $frames->enterCommand($command, 'invoices:send');
        $frames->enterJob($job, 'App\Jobs\SendInvoice');

        $frames->leave($job);
        $frames->leave($job);

        self::assertSame($command, $frames->current()?->owner);
    }

    /**
     * An owner holding no frame changes nothing, even one equal to the owner of
     * a frame: the match is identity, never equality.
     *
     * @return void
     */
    public function testLeavingAnUnknownOwnerChangesNothing(): void
    {
        $frames = new ExecutionFrames;
        $job    = new \stdClass;

        $frames->enterJob($job, 'App\Jobs\SendInvoice');
        $frames->leave(new \stdClass);

        self::assertSame($job, $frames->current()?->owner);
    }

    /**
     * Leaving with nothing on the stack changes nothing and does not fail.
     *
     * @return void
     */
    public function testLeavingAnEmptyStackChangesNothing(): void
    {
        $frames = new ExecutionFrames;

        $frames->leave(new \stdClass);

        self::assertNull($frames->current());
    }

    /**
     * Leaving a frame drops any inner frame an exception orphaned, and only
     * those.
     *
     * @return void
     */
    public function testLeavingPopsThroughAnOrphanedInnerFrame(): void
    {
        $frames   = new ExecutionFrames;
        $base     = new \stdClass;
        $command  = new \stdClass;
        $orphaned = new \stdClass;

        $frames->enterJob($base, 'App\Jobs\Base');
        $frames->enterCommand($command, 'invoices:send');
        $frames->enterJob($orphaned, 'App\Jobs\Orphaned');

        $frames->leave($command);

        self::assertSame($base, $frames->current()?->owner);
        self::assertSame(Origin::QUEUE, $frames->origin());

        $frames->leave($orphaned);

        self::assertSame($base, $frames->current()?->owner, 'The orphaned frame is gone, so leaving it again changes nothing.');
    }

    /**
     * An owner holding two frames leaves its inner one first, which protects
     * against a mutation that searches from the outermost frame.
     *
     * @return void
     */
    public function testAnOwnerHoldingTwoFramesLeavesTheInnerOne(): void
    {
        $frames = new ExecutionFrames;
        $input  = new \stdClass;

        $frames->enterCommand($input, 'invoices:outer');
        $frames->enterCommand($input, 'invoices:inner');

        $frames->leave($input);
        self::assertSame('invoices:outer', $frames->current()?->name);

        $frames->leave($input);
        self::assertNull($frames->current());
    }

    /**
     * A request replaces whatever is on the stack, so the frames beneath it are
     * gone and no longer answer for it.
     *
     * @return void
     */
    public function testARequestReplacesTheStack(): void
    {
        $frames  = new ExecutionFrames;
        $job     = new \stdClass;
        $request = Request::create('/');

        $frames->enterJob($job, 'App\Jobs\SendInvoice');
        $frames->enterRequest($request);

        self::assertSame($request, $frames->current()?->owner);

        $frames->leave($job);

        self::assertSame($request, $frames->current()?->owner);
    }

    /**
     * A new request replaces an earlier one, in every answer.
     *
     * @return void
     */
    public function testANewRequestReplacesAnEarlierOne(): void
    {
        $frames = new ExecutionFrames;
        $later  = Request::create('/later');

        $frames->enterRequest(Request::create('/earlier'));
        $frames->enterRequest($later);

        self::assertSame($later, $frames->request());
        self::assertSame($later, $frames->inboundRequest());
    }

    /**
     * Leaving a request changes nothing: the request's frame lives until the
     * scoped instance dies.
     *
     * @return void
     */
    public function testLeavingTheRequestChangesNothing(): void
    {
        $frames  = new ExecutionFrames;
        $request = Request::create('/');

        $frames->enterRequest($request);
        $frames->leave($request);

        self::assertSame($request, $frames->request());
        self::assertSame(Origin::HTTP, $frames->origin());
    }

    /**
     * The request as the owner of a command's frame leaves that frame alone, so
     * the guard is on the frame's kind and not on what the owner is.
     *
     * @return void
     */
    public function testARequestOwningACommandFrameLeavesOnlyThatFrame(): void
    {
        $frames  = new ExecutionFrames;
        $request = Request::create('/');

        $frames->enterRequest($request);
        $frames->enterCommand($request, 'invoices:send');
        $frames->leave($request);

        self::assertSame(FrameKind::HTTP, $frames->current()?->kind);

        $frames->leave($request);

        self::assertSame(FrameKind::HTTP, $frames->current()?->kind);
    }

    /**
     * Only an innermost request's frame gives the request, so a command or a
     * job inside a request fills no client or route; it comes back when they
     * end.
     *
     * @return void
     */
    public function testRequestIsOnlyTheInnermostFrames(): void
    {
        $frames  = new ExecutionFrames;
        $command = new \stdClass;
        $request = Request::create('/');

        $frames->enterRequest($request);
        self::assertSame($request, $frames->request());

        $frames->enterCommand($command, 'invoices:send');
        self::assertNull($frames->request());

        $frames->enterJob(new \stdClass, 'App\Jobs\SendInvoice');
        self::assertNull($frames->request());

        $frames->leave($command);
        self::assertSame($request, $frames->request());
    }

    /**
     * The inbound request is found beneath any depth of commands and jobs, for
     * identity alone.
     *
     * @return void
     */
    public function testInboundRequestIsFoundBeneathACommandOrAJob(): void
    {
        $frames  = new ExecutionFrames;
        $request = Request::create('/');

        $frames->enterRequest($request);
        self::assertSame($request, $frames->inboundRequest());

        $frames->enterCommand(new \stdClass, 'invoices:send');
        self::assertSame($request, $frames->inboundRequest());

        $frames->enterJob(new \stdClass, 'App\Jobs\SendInvoice');
        self::assertSame($request, $frames->inboundRequest());
    }

    /**
     * With commands and jobs alone on the stack there is no inbound request.
     *
     * @return void
     */
    public function testACommandOrAJobAloneHasNoInboundRequest(): void
    {
        $frames = new ExecutionFrames;

        $frames->enterCommand(new \stdClass, 'invoices:send');
        $frames->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertNull($frames->inboundRequest());
    }

    /**
     * Two stacks share nothing, so a scoped instance forgotten between requests
     * takes all its frames with it.
     *
     * @return void
     */
    public function testNothingIsSharedBetweenInstances(): void
    {
        $first = new ExecutionFrames;

        $first->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertNull((new ExecutionFrames)->current());
    }

    /**
     * Outside a job there is no carried actor.
     *
     * @return void
     */
    public function testOutsideAJobNoActorIsCarried(): void
    {
        $frames = new ExecutionFrames;

        self::assertNull($frames->carriedActor());

        $frames->enterRequest(Request::create('/'));
        $frames->enterCommand(new \stdClass, 'invoices:send');

        self::assertNull($frames->carriedActor());
    }

    /**
     * The innermost job decides whose actor is carried, a job carrying none
     * included, and the outer job's comes back when it ends. A command inside a
     * job keeps the job's.
     *
     * @return void
     */
    public function testTheInnermostJobsCarriedActorApplies(): void
    {
        $frames = new ExecutionFrames;
        $outer  = new ActorSnapshot(Reference::of('user', 'user-1'), 'web');
        $inner  = new \stdClass;

        $frames->enterJob(new \stdClass, 'App\Jobs\Outer', $outer);
        $frames->enterCommand(new \stdClass, 'invoices:send');

        self::assertSame($outer, $frames->carriedActor());

        $frames->enterJob($inner, 'App\Jobs\Inner');

        self::assertNull($frames->carriedActor());

        $frames->leave($inner);

        self::assertSame($outer, $frames->carriedActor());
    }

    /**
     * A user is a leftover by identity and by guard: the very object, on the
     * guard that held it, from a job anywhere on the stack.
     *
     * @return void
     */
    public function testALeftoverIsTheVeryObjectOnItsGuard(): void
    {
        $frames = new ExecutionFrames;
        $user   = new \stdClass;

        self::assertFalse($frames->isLeftover('web', $user));

        $frames->enterJob(new \stdClass, 'App\Jobs\Outer', null, ['web' => $user]);
        $frames->enterJob(new \stdClass, 'App\Jobs\Inner');

        self::assertTrue($frames->isLeftover('web', $user));
        self::assertFalse($frames->isLeftover('api', $user));
        self::assertFalse($frames->isLeftover('web', new \stdClass));
    }

    /**
     * Leaving a job takes its leftovers with it.
     *
     * @return void
     */
    public function testALeftoverEndsWithItsJob(): void
    {
        $frames = new ExecutionFrames;
        $user   = new \stdClass;
        $job    = new \stdClass;

        $frames->enterJob($job, 'App\Jobs\Outer', null, ['web' => $user]);
        $frames->leave($job);

        self::assertFalse($frames->isLeftover('web', $user));
    }
}
