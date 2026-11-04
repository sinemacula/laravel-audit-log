<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Querying;

use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;

/**
 * A field reader that answers each path from the map it is given, a value to
 * reveal, a state to keep the field sealed in, or an exception to throw, and
 * `encrypted` for any other path, as the package's own reader does. It keeps
 * every field it was asked for, in order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RevealingFieldReader implements FieldReader
{
    /** @var list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField> Each field it was asked for, in order. */
    private array $fields = [];

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, array<array-key, mixed>|scalar|\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState|\Throwable|null>  $answers
     */
    public function __construct(

        /** What to answer for each path: a value, a state, or what to throw. */
        private readonly array $answers = [],
    ) {}

    /**
     * The answer the map gives for the field's path, `encrypted` for a path it
     * does not name.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EncryptedField  $field
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldReading
     *
     * @throws \Throwable
     */
    #[\Override]
    public function read(#[\SensitiveParameter] EncryptedField $field): FieldReading
    {
        $this->fields[] = $field;

        if (!array_key_exists($field->path, $this->answers)) {
            return FieldReading::sealed(FieldState::ENCRYPTED);
        }

        $answer = $this->answers[$field->path];

        if ($answer instanceof \Throwable) {
            throw $answer;
        }

        return $answer instanceof FieldState ? FieldReading::sealed($answer) : FieldReading::revealed($answer);
    }

    /**
     * Each field it was asked for, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>
     */
    public function fields(): array
    {
        return $this->fields;
    }

    /**
     * The path of each field it was asked for, in order.
     *
     * @return list<string>
     */
    public function paths(): array
    {
        return array_map(static fn (EncryptedField $field): string => $field->path, $this->fields);
    }
}
