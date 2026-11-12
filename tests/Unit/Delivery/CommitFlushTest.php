<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\CommitFlush;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;

/**
 * Unit tests for the audit work waiting on one commit: every piece runs, and
 * the first failure is thrown once all have.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommitFlush::class)]
final class CommitFlushTest extends TestCase
{
    /** @var list<string> What ran, in order. */
    private array $ran = [];

    /**
     * Work runs in the order it was added.
     *
     * @return void
     */
    public function testRunsTheWorkInOrder(): void
    {
        $flush = $this->flush();

        $flush->add($this->noting('first'));
        $flush->add($this->noting('second'));

        $flush->run();

        self::assertSame(['first', 'second'], $this->ran);
    }

    /**
     * A failure stops no other work, and the first failure is what leaves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneFailureStopsNoOtherWork(): void
    {
        $first = new \RuntimeException('First.');
        $flush = $this->flush();

        $flush->add(static function () use ($first): never {
            throw $first;
        });

        $flush->add($this->noting('second'));

        try {
            $flush->run();

            self::fail('Expected the failure to leave once all the work has run.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($first, $thrown);
        }

        self::assertSame(['second'], $this->ran);
    }

    /**
     * Only one exception can leave a commit, so a later failure is reported
     * inside the write guard rather than lost.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALaterFailureIsReported(): void
    {
        $reporter = new RecordingExceptionHandler;
        $guard    = new WriteGuard;
        $active   = null;
        $later    = new \RuntimeException('Later.');
        $flush    = $this->flush($reporter, $guard);

        $flush->add(static function (): never {
            throw new \RuntimeException('First.');
        });

        $last = new \RuntimeException('Last.');

        $flush->add(static function () use ($later): never {
            throw $later;
        });

        $flush->add(static function () use ($last): never {
            throw $last;
        });

        try {
            $flush->run();
        } catch (\RuntimeException) {
            $active = $guard->isActive();
        }

        self::assertSame([$later, $last], $reporter->reports());
        self::assertFalse($active, 'The guard is released once the report has run.');
    }

    /**
     * A reporter that fails over a later failure stops nothing: the first
     * failure still leaves.
     *
     * @return void
     */
    public function testABrokenReporterStopsNothing(): void
    {
        $flush = $this->flush(new RecordingExceptionHandler(throwsOnReport: true));

        foreach (['First.', 'Later.'] as $message) {
            $flush->add(static function () use ($message): never {
                throw new \RuntimeException($message);
            });
        }

        $this->expectExceptionMessage('First.');

        $flush->run();
    }

    /**
     * A transaction found aborted runs no work: each abandon step is told what
     * showed it, and work with no such step is simply dropped.
     *
     * @return void
     */
    public function testAnAbortedTransactionOnlyAbandons(): void
    {
        $aborted = new \PDOException('Aborted.');
        $given   = [];
        $flush   = $this->flush();

        $flush->add($this->noting('dropped'));
        $flush->add($this->noting('written'), static function (\Throwable $failure) use (&$given): void {
            $given[] = $failure;
        });

        $flush->doom($aborted);
        $flush->run();

        self::assertSame([], $this->ran);
        self::assertSame([$aborted], $given);
    }

    /**
     * Work runs once, whoever runs the flush again.
     *
     * @return void
     */
    public function testWorkRunsOnce(): void
    {
        $flush = $this->flush();

        $flush->add($this->noting('once'));

        $flush->run();
        $flush->run();

        self::assertSame(['once'], $this->ran);
    }

    /**
     * Whether work is expected is known from the moment it is deferred, though
     * a nested transaction's work joins only when that transaction commits.
     *
     * @return void
     */
    public function testKnowsWhetherWorkIsExpected(): void
    {
        $flush = $this->flush();

        self::assertFalse($flush->isExpecting());

        $flush->expect();

        self::assertTrue($flush->isExpecting());
    }

    /**
     * A flush whose reporter, and write guard, are the ones given.
     *
     * @param  ?\Tests\Fixtures\Privacy\RecordingExceptionHandler  $reporter
     * @param  ?\SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @return \SineMacula\Laravel\AuditLog\Delivery\CommitFlush
     */
    private function flush(?RecordingExceptionHandler $reporter = null, ?WriteGuard $guard = null): CommitFlush
    {
        $container = new Container;

        $container->instance(ExceptionHandler::class, $reporter ?? new RecordingExceptionHandler);
        $container->instance(WriteGuard::class, $guard ?? new WriteGuard);

        return new CommitFlush($container);
    }

    /**
     * Work that notes it ran.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function noting(string $name): \Closure
    {
        return function () use ($name): void {
            $this->ran[] = $name;
        };
    }
}
