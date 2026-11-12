<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\AuthManager;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Context;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\NullOutput;
use Tests\TestCase;

/**
 * Feature tests for the frames commands enter and leave.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrackCommandFrames::class)]
final class TrackCommandFramesTest extends TestCase
{
    /**
     * Bind the frames as the provider does, which keeps an existing binding.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->scopedIf(ExecutionFrames::class);
    }

    /**
     * Put the current container back, for a test that replaced it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->app);

        parent::tearDown();
    }

    /**
     * A command starting enters a frame with its name, owned by its input.
     *
     * @return void
     */
    public function testCommandStartingEntersAFrameWithItsName(): void
    {
        $input = new ArrayInput([]);

        (new TrackCommandFrames)($this->starting('invoices:send', $input));

        $frame = $this->frames()->current();

        self::assertNotNull($frame);
        self::assertSame('invoices:send', $frame->name);
        self::assertSame($input, $frame->owner);
        self::assertSame(Origin::CONSOLE, $this->frames()->origin());
    }

    /**
     * A command the framework could not name has an empty name, kept as none.
     *
     * @return void
     */
    public function testACommandWithAnEmptyNameHasNone(): void
    {
        (new TrackCommandFrames)($this->starting('', new ArrayInput([])));

        self::assertNotNull($this->frames()->current());
        self::assertNull($this->frames()->current()->name);
    }

    /**
     * A command finishing leaves its frame.
     *
     * @return void
     */
    public function testCommandFinishedLeavesIt(): void
    {
        $input = new ArrayInput([]);

        (new TrackCommandFrames)($this->starting('invoices:send', $input));
        (new TrackCommandFrames)($this->finished('invoices:send', $input));

        self::assertNull($this->frames()->current());
    }

    /**
     * A nested command's finish restores its caller's frame.
     *
     * @return void
     */
    public function testANestedCommandRestoresItsCaller(): void
    {
        $outer = new ArrayInput([]);
        $inner = new ArrayInput([]);

        (new TrackCommandFrames)($this->starting('invoices:outer', $outer));
        (new TrackCommandFrames)($this->starting('invoices:inner', $inner));
        (new TrackCommandFrames)($this->finished('invoices:inner', $inner));

        self::assertSame('invoices:outer', $this->frames()->current()?->name);
    }

    /**
     * Another command's finish, even of the same name, leaves the frame: the
     * match is on the input.
     *
     * @return void
     */
    public function testAnotherCommandsFinishLeavesItInPlace(): void
    {
        $input = new ArrayInput([]);

        (new TrackCommandFrames)($this->starting('invoices:send', $input));
        (new TrackCommandFrames)($this->finished('invoices:send', new ArrayInput([])));

        self::assertSame($input, $this->frames()->current()?->owner);
    }

    /**
     * The current container's frames are used on every event, for Octane.
     *
     * @return void
     */
    public function testTheFramesOfTheCurrentContainerAreUsed(): void
    {
        $booted  = $this->frames();
        $sandbox = new Container;

        $sandbox->singleton(ExecutionFrames::class);

        Container::setInstance($sandbox);

        (new TrackCommandFrames)($this->starting('invoices:send', new ArrayInput([])));

        self::assertNull($booted->current());
        self::assertSame('invoices:send', $sandbox->make(ExecutionFrames::class)->current()?->name);
    }

    /**
     * Context is the same after a command's events as before them.
     *
     * @return void
     */
    public function testContextIsLeftAlone(): void
    {
        Context::add('tenant', 'acme');
        Context::addHidden('audit-log.request_id', 'app:request-1');

        $input = new ArrayInput([]);

        (new TrackCommandFrames)($this->starting('invoices:send', $input));
        (new TrackCommandFrames)($this->finished('invoices:send', $input));

        self::assertSame(['tenant' => 'acme'], Context::all());
        self::assertSame(['audit-log.request_id' => 'app:request-1'], Context::allHidden());
    }

    /**
     * Neither event reaches the auth manager, so no guard is read or reset.
     *
     * @return void
     */
    public function testTheGuardsAreLeftAlone(): void
    {
        $auth = \Mockery::mock(AuthManager::class);
        $auth->shouldNotReceive('guard');

        $this->app?->instance('auth', $auth);

        $input = new ArrayInput([]);

        (new TrackCommandFrames)($this->starting('invoices:send', $input));
        (new TrackCommandFrames)($this->finished('invoices:send', $input));

        self::assertNull($this->frames()->current());
    }

    /**
     * The event of a command starting.
     *
     * @param  string  $name
     * @param  \Symfony\Component\Console\Input\InputInterface  $input
     * @return \Illuminate\Console\Events\CommandStarting
     */
    private function starting(string $name, InputInterface $input): CommandStarting
    {
        return new CommandStarting($name, $input, new NullOutput);
    }

    /**
     * The event of a command finishing.
     *
     * @param  string  $name
     * @param  \Symfony\Component\Console\Input\InputInterface  $input
     * @return \Illuminate\Console\Events\CommandFinished
     */
    private function finished(string $name, InputInterface $input): CommandFinished
    {
        return new CommandFinished($name, $input, new NullOutput, 0);
    }

    /**
     * The frames of the application under test.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }
}
