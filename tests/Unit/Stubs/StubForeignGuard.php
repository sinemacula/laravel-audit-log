<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * A guard without Laravel's `GuardHelpers` that records every method it is
 * asked and fails the test on anything but `hasUser()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubForeignGuard implements Guard
{
    /** @var list<string> The methods the guard was asked, in order. */
    public array $calls = [];

    /** @var object What it holds where a guard using the trait would, so reading it gives a test the wrong answer. */
    public readonly object $user;

    /**
     * Constructor.
     *
     * @param  bool  $holdsUser
     */
    public function __construct(

        /** What `hasUser()` answers. */
        private readonly bool $holdsUser = true,
    ) {
        $this->user = new \stdClass;
    }

    /**
     * Whether the guard holds a user.
     *
     * @return bool
     */
    #[\Override]
    public function hasUser(): bool
    {
        $this->calls[] = 'hasUser';

        return $this->holdsUser;
    }

    /**
     * Fail the test: this guard is asked only `hasUser()`.
     *
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function check(): never
    {
        $this->refuse('check');
    }

    /**
     * Fail the test: this guard is asked only `hasUser()`.
     *
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function guest(): never
    {
        $this->refuse('guest');
    }

    /**
     * Fail the test: this guard is asked only `hasUser()`.
     *
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function user(): never
    {
        $this->refuse('user');
    }

    /**
     * Fail the test: this guard is asked only `hasUser()`.
     *
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function id(): never
    {
        $this->refuse('id');
    }

    /**
     * Fail the test: this guard is asked only `hasUser()`.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function validate(array $credentials = []): never
    {
        $this->refuse('validate');
    }

    /**
     * Fail the test: this guard is asked only `hasUser()`.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function setUser(Authenticatable $user): never
    {
        $this->refuse('setUser');
    }

    /**
     * Note the call, then fail the test.
     *
     * @param  string  $method
     * @return never
     *
     * @throws \LogicException
     */
    private function refuse(string $method): never
    {
        $this->calls[] = $method;

        throw new \LogicException(sprintf('A foreign guard was asked `%s()`.', $method));
    }
}
