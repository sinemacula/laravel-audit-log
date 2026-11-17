<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Support;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Symfony\Component\HttpFoundation\Response;

/**
 * An HTTP kernel that is not Laravel's: it takes the middleware lists the
 * application builder hands it, but has nothing to prepend to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainHttpKernel implements Kernel
{
    /** @var array<int, class-string> The global middleware it was handed. */
    public array $globalMiddleware = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** The application the kernel serves. */
        private readonly Application $app,
    ) {}

    /**
     * Bootstrap nothing.
     *
     * @return void
     */
    #[\Override]
    public function bootstrap(): void {}

    /**
     * Answer every request with an empty response.
     *
     * @param  mixed  $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    #[\Override]
    public function handle(mixed $request): Response
    {
        return new Response;
    }

    /**
     * Finish nothing.
     *
     * @param  mixed  $request
     * @param  mixed  $response
     * @return void
     */
    #[\Override]
    public function terminate(mixed $request, mixed $response): void {}

    /**
     * The application the kernel serves.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    #[\Override]
    public function getApplication(): Application
    {
        return $this->app;
    }

    /**
     * Keep the global middleware.
     *
     * @param  array<int, class-string>  $middleware
     * @return void
     */
    public function setGlobalMiddleware(array $middleware): void
    {
        $this->globalMiddleware = $middleware;
    }

    /**
     * Ignore the middleware groups.
     *
     * @param  array<string, array<int, string>>  $groups
     * @return void
     */
    public function setMiddlewareGroups(array $groups): void {}

    /**
     * Ignore the middleware aliases.
     *
     * @param  array<string, class-string>  $aliases
     * @return void
     */
    public function setMiddlewareAliases(array $aliases): void {}
}
