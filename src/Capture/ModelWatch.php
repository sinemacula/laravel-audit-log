<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * What an application watches of one model class: the exact class, the code
 * segment its changes are stored under, and the fields kept, each with its
 * handling.
 *
 * A watch is checked from the class alone, by reflection, and no model is
 * built. The class must be a concrete Eloquent model outside the package's own
 * namespace, so the package's read model is never watched. The segment is one
 * code segment, short enough that its longest code fits the code column, and
 * none the package's own codes are stored under. The fields are 1 to 64 names
 * of columns, each once, never `changes`, which an update's record keeps its
 * changes under, and never beginning `_audit`; a field given without a handling
 * is retained.
 *
 * Each of the five changes is recorded under its own definition, in the
 * `change` category at version 1, with every field the watch does not name
 * dropped: a snapshot rules each field at its name, an update rules each
 * field's value before and after the change, and a restore rules both. A field
 * encrypted is encrypted under the key of the model, the record's subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ModelWatch
{
    /** @var int Most fields one watch keeps. */
    public const int MAX_FIELDS = 64;

    /** @var list<string> The segments the package's own codes are stored under, which no watched model's changes are. */
    public const array RESERVED_SEGMENTS = ['authentication', 'session', 'account', 'authorization', 'mfa', 'sso', 'audit_log'];

    /** @var string The category every watched model's changes are stored under. */
    public const string CATEGORY = 'change';

    /** @var string Pattern of the segment: a lower-case letter, then up to 176 lower-case letters, digits or underscores, so its longest code fits 191 bytes. */
    private const string SEGMENT_PATTERN = '/\A[a-z][a-z0-9_]{0,176}\z/';

    /** @var string Pattern of a field: a letter or underscore, then up to 63 letters, digits or underscores. */
    private const string FIELD_PATTERN = '/\A[A-Za-z_][A-Za-z0-9_]{0,63}\z/';

    /** @var string The key an update's record keeps its changes under, which no field may be. */
    private const string CHANGES = 'changes';

    /** @var string The prefix of the package's own metadata, which no field may begin with. */
    private const string RESERVED_FIELD_PREFIX = '_audit';

    /** @var int Most bytes of a refused field's name a message shows, cleaned. */
    private const int FIELD_SHOWN_BYTES = 64;

    /** @var string The namespace of the package, whose models are never watched. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /**
     * Constructor.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $as
     * @param  array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>  $fields
     */
    private function __construct(

        /** The model class watched, exactly, as PHP names it. */
        public string $class,

        /** The code segment the model's changes are stored under. */
        public string $as,

        /** The fields kept, each with its handling, in the order given. */
        public array $fields,
    ) {}

    /**
     * A watch of the model class under the segment, keeping the fields: a name
     * given alone is retained, and a name given as a key is handled as its
     * value says.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $class
     * @param  string  $as
     * @param  array<array-key, mixed>  $fields
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function of(string $class, string $as, array $fields): self
    {
        return new self(self::modelClass($class), self::segment($as), self::fieldsOf($fields));
    }

    /**
     * The definitions the model's changes are recorded under, by change.
     *
     * @return array<string, \SineMacula\Laravel\AuditLog\Definitions\EventDefinition>
     *
     * @throws \InvalidArgumentException
     */
    public function definitions(): array
    {
        $definitions = [];

        foreach (ModelEvent::cases() as $change) {
            $definitions[$change->value] = $this->definitionOf($change);
        }

        return $definitions;
    }

    /**
     * The code a change of the model is stored under.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $change
     * @return string
     */
    public function codeOf(ModelEvent $change): string
    {
        return $change->codeFor($this->as);
    }

    /**
     * How the field is handled: as the watch names it, or dropped, as every
     * field it does not name is.
     *
     * @param  string  $field
     * @return \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling
     */
    public function handlingOf(string $field): FieldHandling
    {
        return $this->fields[$field] ?? FieldHandling::DROP;
    }

    /**
     * Whether the field is handled explicitly: by any handling but retaining it
     * as it is, so its value is never kept in plaintext as read.
     *
     * @param  string  $field
     * @return bool
     */
    public function isExplicit(string $field): bool
    {
        return $this->handlingOf($field) !== FieldHandling::RETAIN;
    }

    /**
     * Whether the other watch is of the same class, under the same segment,
     * keeping the same fields with the same handlings, in any order.
     *
     * @param  self  $other
     * @return bool
     */
    public function equals(self $other): bool
    {
        $mine   = $this->fields;
        $theirs = $other->fields;

        ksort($mine, SORT_STRING);
        ksort($theirs, SORT_STRING);

        return $this->class === $other->class && $this->as === $other->as && $mine === $theirs;
    }

    /**
     * The definition of a change: the snapshot's fields for a change that keeps
     * one, and each field before and after for a change that keeps the changes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $change
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    private function definitionOf(ModelEvent $change): EventDefinition
    {
        $definition = EventDefinition::for($this->codeOf($change))->category(self::CATEGORY);

        foreach ($this->fields as $field => $handling) {
            if ($change !== ModelEvent::UPDATED) {
                $definition = self::ruled($definition, $field, $handling);
            }

            if ($change !== ModelEvent::UPDATED && $change !== ModelEvent::RESTORED) {
                continue;
            }

            $definition = self::ruled($definition, self::CHANGES . '.' . $field . '.before', $handling);
            $definition = self::ruled($definition, self::CHANGES . '.' . $field . '.after', $handling);
        }

        return $definition;
    }

    /**
     * The definition with a rule of the handling at the path, an encrypted
     * field owned by the record's subject.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    private static function ruled(EventDefinition $definition, string $path, FieldHandling $handling): EventDefinition
    {
        return $handling === FieldHandling::ENCRYPT
            ? $definition->encrypt($path, KeyOwner::SUBJECT)
            : $definition->rule($path, $handling);
    }

    /**
     * The model class as PHP names it, refusing one that does not exist, is not
     * an Eloquent model, is abstract, or is the package's own.
     *
     * @param  string  $class
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function modelClass(string $class): string
    {
        if (!class_exists($class) || !is_a($class, Model::class, true)) {
            throw new \InvalidArgumentException(sprintf('`%s` is not an Eloquent model class.', $class));
        }

        $reflection = new \ReflectionClass($class);

        if ($reflection->isAbstract()) {
            throw new \InvalidArgumentException(sprintf('`%s` is abstract; a watched model is a class its rows are built as.', $class));
        }

        if (str_starts_with($reflection->getName(), self::PACKAGE_NAMESPACE)) {
            throw new \LogicException('The package\'s own models are never watched.');
        }

        return $reflection->getName();
    }

    /**
     * The segment, refusing one outside its grammar or reserved for the
     * package's own codes.
     *
     * @param  string  $as
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function segment(string $as): string
    {
        if (preg_match(self::SEGMENT_PATTERN, $as) !== 1) {
            throw new \InvalidArgumentException('A watched model\'s segment must be a lower-case letter, then up to 176 lower-case letters, digits or underscores.');
        }

        if (in_array($as, self::RESERVED_SEGMENTS, true)) {
            throw new \InvalidArgumentException(sprintf('The segment `%s` is reserved for the package\'s own codes.', $as));
        }

        return $as;
    }

    /**
     * The fields, each with its handling, in the order given: a name given
     * alone is retained. Refused unless there are 1 to 64, each a name a watch
     * can keep, given once, with a handling.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>
     *
     * @throws \InvalidArgumentException
     */
    private static function fieldsOf(array $fields): array
    {
        if ($fields === [] || count($fields) > self::MAX_FIELDS) {
            throw new \InvalidArgumentException(sprintf('A watched model keeps from 1 to %d fields.', self::MAX_FIELDS));
        }

        $handled = [];

        foreach ($fields as $key => $value) {
            [$field, $handling] = is_int($key) ? [$value, FieldHandling::RETAIN] : [$key, $value];

            $field = self::field($field);

            if (!$handling instanceof FieldHandling) {
                throw new \InvalidArgumentException(sprintf('The field `%s` is given a `%s`, not a `FieldHandling`.', $field, get_debug_type($handling)));
            }

            if (isset($handled[$field])) {
                throw new \InvalidArgumentException(sprintf('The field `%s` is watched twice.', $field));
            }

            $handled[$field] = $handling;
        }

        return $handled;
    }

    /**
     * The field's name, refusing anything but a name a watch can keep.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $field
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function field(mixed $field): string
    {
        if (!is_string($field)) {
            throw new \InvalidArgumentException(sprintf('A watched field is named by a string, not a `%s`.', get_debug_type($field)));
        }

        if (preg_match(self::FIELD_PATTERN, $field) !== 1 || $field === self::CHANGES || str_starts_with($field, self::RESERVED_FIELD_PREFIX)) {
            $message = 'The field `%s` cannot be watched: a field is a letter or underscore, then up to 63 letters, digits or underscores, '
                . 'and neither `changes` nor beginning `_audit`.';

            throw new \InvalidArgumentException(sprintf($message, TextSanitizer::clean($field, self::FIELD_SHOWN_BYTES)));
        }

        return $field;
    }
}
