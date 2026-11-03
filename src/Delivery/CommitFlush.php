<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * The audit work waiting on one outermost transaction's commit, run as one
 * commit callback: every piece of work runs whatever another does, the first
 * failure is thrown once all have run, and any later one is reported, since
 * only one exception can leave the commit. Everything thrown here has already
 * been sanitised and handled by the failure path.
 *
 * When the transaction was found aborted, so its commit was really a rollback,
 * nothing runs but each abandon step.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommitFlush
{
    /** @var list<array{work: \Closure(): void, abandon: ?\Closure(\Throwable): void}> The work ready to run, oldest first. */
    private array $entries = [];

    /** @var bool Whether any work was deferred on this transaction or one nested in it, whether or not it is ready. */
    private bool $expecting = false;

    /** @var ?\Throwable What showed the transaction was already aborted, if anything did. */
    private ?\Throwable $aborted = null;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the reporter and the write guard are resolved from when a later failure is reported. */
        private readonly Container $container,
    ) {}

    /**
     * Note that work was deferred, though it may join only when a nested
     * transaction commits, after the commit it depends on has been asked for.
     *
     * @return void
     */
    public function expect(): void
    {
        $this->expecting = true;
    }

    /**
     * Whether any work was deferred on the transaction.
     *
     * @return bool
     */
    public function isExpecting(): bool
    {
        return $this->expecting;
    }

    /**
     * Add work to run, and how to abandon it if the commit proves a rollback.
     *
     * @param  \Closure(): void  $work
     * @param  ?\Closure(\Throwable): void  $abandon
     * @return void
     */
    public function add(#[\SensitiveParameter] \Closure $work, #[\SensitiveParameter] ?\Closure $abandon = null): void
    {
        $this->entries[] = ['work' => $work, 'abandon' => $abandon];
    }

    /**
     * Mark the transaction as already aborted, so nothing waiting on it runs.
     *
     * @param  \Throwable  $aborted
     * @return void
     */
    public function doom(#[\SensitiveParameter] \Throwable $aborted): void
    {
        $this->aborted = $aborted;
    }

    /**
     * Run all the work and throw the first failure at the end, or abandon it
     * all if the transaction was aborted. Each piece of work runs once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function run(): void
    {
        $entries       = $this->entries;
        $this->entries = [];
        $first         = null;

        foreach ($entries as $entry) {
            try {
                $this->runEntry($entry['work'], $entry['abandon']);
            } catch (\Throwable $failure) {
                if ($first !== null) {
                    $this->report($failure);

                    continue;
                }

                $first = $failure;
            }
        }

        if ($first !== null) {
            throw $first;
        }
    }

    /**
     * Run the work, or, when the transaction was aborted, its abandon step if
     * it has one.
     *
     * @param  \Closure(): void  $work
     * @param  ?\Closure(\Throwable): void  $abandon
     * @return void
     *
     * @throws \Throwable
     *
     * @phpstan-ignore throws.unusedType
     */
    private function runEntry(#[\SensitiveParameter] \Closure $work, #[\SensitiveParameter] ?\Closure $abandon): void
    {
        if ($this->aborted === null) {

            $work();

            return;
        }

        if ($abandon === null) {
            return;
        }

        $abandon($this->aborted);
    }

    /**
     * Report a failure no exception can carry out of the commit, inside the
     * write guard, ignoring a reporter that fails.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function report(#[\SensitiveParameter] \Throwable $failure): void
    {
        $container = $this->container;

        try {
            $container->make(WriteGuard::class)->during(static function () use ($container, $failure): void {
                $container->make(ExceptionHandler::class)->report($failure);
            });
        } catch (\Throwable) {
            // Only one exception can leave a commit, and the first is on its
            // way out, so there is nowhere left to say this one
        }
    }
}
