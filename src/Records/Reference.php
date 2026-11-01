<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\ClassMorphViolationException;
use Illuminate\Database\Eloquent\Model;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Symfony\Component\Uid\AbstractUid;

/**
 * Something a record refers to, as a type and an id: the actor, the subject,
 * the principal or the tenant. A model is referred to by its morph class, or by
 * its class name when an enforced morph map omits it, and by its key.
 *
 * Both parts are strings from 1 to 191 characters with no control characters,
 * validated and never truncated, trimmed or case-folded: an id is kept exactly
 * as given, so `42`, `007`, an integer beyond `PHP_INT_MAX` given as a string,
 * and a UUID or ULID in either case each stay what they are. A reference never
 * reads a model's other attributes, so it can never carry them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, string>
 */
final readonly class Reference implements Arrayable
{
    /** @var int Longest type or id, in characters: the reference columns. */
    public const int MAX_CHARACTERS = 191;

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The type: a morph class, a class name or any name the application uses. */
        public string $type,

        /** The id, exactly as given, as a string. */
        public string $id,
    ) {
        self::check($type, 'type');
        self::check($id, 'id');
    }

    /**
     * A reference to the type and id given; an integer id is kept as its
     * decimal string.
     *
     * @param  string  $type
     * @param  int|string  $id
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(string $type, int|string $id): self
    {
        return new self($type, (string) $id);
    }

    /**
     * A reference to the model: its morph class, or its class name when an
     * enforced morph map omits it, and its key as a string. The model must have
     * a key, a string, an integer or a UUID or ULID object; a deleted model
     * that still holds its key is referred to as before.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function to(Model $model): self
    {
        return new self(self::morphClassOf($model), self::keyOf($model));
    }

    /**
     * Whether the other reference has exactly the same type and id.
     *
     * @param  self  $other
     * @return bool
     */
    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->id === $other->id;
    }

    /**
     * The reference as the type and id pair a record stores.
     *
     * @return array{type: string, id: string}
     */
    #[\Override]
    public function toArray(): array
    {
        return ['type' => $this->type, 'id' => $this->id];
    }

    /**
     * Refuse a part that is empty, longer than the reference columns, or not
     * already clean text.
     *
     * @param  string  $value
     * @param  'id'|'type'  $part
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function check(string $value, string $part): void
    {
        if ($value === '' || mb_strlen($value, 'UTF-8') > self::MAX_CHARACTERS || !TextSanitizer::isClean($value)) {
            throw new \InvalidArgumentException(sprintf('A reference\'s %s must be from 1 to %d characters, with no control characters.', $part, self::MAX_CHARACTERS));
        }
    }

    /**
     * The model's morph class, or its class name when an enforced morph map
     * omits it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function morphClassOf(Model $model): string
    {
        try {
            return $model->getMorphClass();
        } catch (ClassMorphViolationException) {
            return $model::class;
        }
    }

    /**
     * The model's key as a string, read without touching any other attribute.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        if ($key === null) {
            throw new \InvalidArgumentException('A model must have a key before it can be referenced; save it first.');
        }

        if (is_string($key)) {
            return $key;
        }

        if (is_int($key)) {
            return (string) $key;
        }

        if ($key instanceof UuidInterface || $key instanceof AbstractUid) {
            return $key->toString();
        }

        throw new \InvalidArgumentException(sprintf('A model\'s key must be a string or an integer to be referenced; it is %s.', get_debug_type($key)));
    }
}
