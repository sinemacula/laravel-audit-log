<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;

/**
 * A model whose `email` accessor, array, JSON and string forms and query
 * builder all throw, so a test fails if referring to it reads more than its
 * key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubSealedUser extends Model
{
    /**
     * Fail the test if the model is cast to a string.
     *
     * @return never
     *
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function __toString(): never
    {
        throw new \LogicException('The model was cast to a string.');
    }

    /**
     * Fail the test if the model is turned into an array.
     *
     * @return never
     *
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function toArray(): never
    {
        throw new \LogicException('The model was turned into an array.');
    }

    /**
     * Fail the test if the model is turned into JSON.
     *
     * @param  mixed  $options
     * @return never
     *
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function toJson(mixed $options = 0): never
    {
        throw new \LogicException('The model was turned into JSON.');
    }

    /**
     * Fail the test if the model is serialised for JSON.
     *
     * @return never
     *
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function jsonSerialize(): never
    {
        throw new \LogicException('The model was serialised for JSON.');
    }

    /**
     * Fail the test if the model is queried.
     *
     * @return never
     *
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function newQuery(): never
    {
        throw new \LogicException('The model was queried.');
    }

    /**
     * The email, whose accessor fails the test if it is read; the accessor, not
     * this method, throws.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<never, never>
     *
     * @throws \LogicException
     *
     * @phpstan-ignore throws.unusedType
     */
    protected function email(): Attribute
    {
        return Attribute::make(get: static fn (): never => throw new \LogicException('The email attribute was read.'));
    }
}
