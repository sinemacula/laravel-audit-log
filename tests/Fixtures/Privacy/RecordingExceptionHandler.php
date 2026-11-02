<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Privacy;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * An exception handler that keeps what it is asked to report and, when told,
 * then throws from `report()`, as a broken reporter would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingExceptionHandler implements ExceptionHandler
{
    /** @var list<\Throwable> What it was asked to report, in order. */
    private array $reports = [];

    /**
     * Constructor.
     *
     * @param  bool  $throwsOnReport
     */
    public function __construct(

        /** Whether `report()` throws once it has kept the exception. */
        private readonly bool $throwsOnReport = false,
    ) {}

    /**
     * Keep the exception, then throw when told to.
     *
     * @param  \Throwable  $e
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function report(\Throwable $e): void
    {
        $this->reports[] = $e;

        if ($this->throwsOnReport) {
            throw new \RuntimeException('The reporter failed.');
        }
    }

    /**
     * Report everything.
     *
     * @param  \Throwable  $e
     * @return bool
     */
    #[\Override]
    public function shouldReport(\Throwable $e): bool
    {
        return true;
    }

    /**
     * Render a bare response.
     *
     * @param  mixed  $request
     * @param  \Throwable  $e
     * @return \Symfony\Component\HttpFoundation\Response
     */
    #[\Override]
    public function render(mixed $request, \Throwable $e): Response
    {
        return new Response('', 500);
    }

    /**
     * Render nothing to the console.
     *
     * @param  mixed  $output
     * @param  \Throwable  $e
     * @return void
     */
    #[\Override]
    public function renderForConsole(mixed $output, \Throwable $e): void {}

    /**
     * What it was asked to report, in order.
     *
     * @return list<\Throwable>
     */
    public function reports(): array
    {
        return $this->reports;
    }
}
