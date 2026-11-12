<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Export;

/**
 * Validates an OCSF event offline against the pinned schema's classes, each
 * resolved by `OcsfSchemaBuilder` into one file.
 *
 * It checks requirements, undeclared attributes, types, enums, the
 * `at_least_one` and `just_one` constraints, and the `type_uid` and `class_uid`
 * arithmetic; a profile's attribute applies only when `metadata.profiles` names
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @phpstan-type Attribute array{requirement: string, type: string, is_array: bool, enum?: array<array-key, string>, profile?: string}
 * @phpstan-type Definition array{attributes: array<string, array{requirement: string, type: string, is_array: bool, enum?: array<array-key, string>, profile?: string}>, constraints: array<string, list<string>>}
 * @phpstan-type Schema array{name: string, caption: string, category: string, category_uid: int, uid: int, class_uid: int, attributes: array<string, array{requirement: string, type: string, is_array: bool, enum?: array<array-key, string>, profile?: string}>, constraints: array<string, list<string>>, objects: array<string, array{attributes: array<string, array{requirement: string, type: string, is_array: bool, enum?: array<array-key, string>, profile?: string}>, constraints: array<string, list<string>>}>, types: array<string, string>}
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @formatter:on
 */
final readonly class OcsfValidator
{
    /** @var string The pinned schema, as built from its tag. */
    public const string ROOT = __DIR__ . '/ocsf/1.9.0';

    /** @var list<string> The classes the pinned schema resolves, one file each. */
    public const array CLASSES = ['base_event', 'api_activity'];

    /** @var string The generic object, whose contents are free. */
    private const string FREE_OBJECT = 'object';

    /**
     * Constructor.
     *
     * @param  array<int, Schema>  $schemas
     */
    public function __construct(

        /** The resolved classes, by `class_uid`. */
        private array $schemas,
    ) {}

    /**
     * A validator of the pinned schema's classes.
     *
     * @return self
     *
     * @throws \JsonException
     */
    public static function pinned(): self
    {
        $schemas = [];

        foreach (self::CLASSES as $class) {
            $schema = self::load($class);

            $schemas[$schema['class_uid']] = $schema;
        }

        return new self($schemas);
    }

    /**
     * The pinned schema's class of the name, as resolved.
     *
     * @param  string  $class
     * @return Schema
     *
     * @throws \UnexpectedValueException
     */
    public static function schema(string $class): array
    {
        if (!in_array($class, self::CLASSES, true)) {
            throw new \UnexpectedValueException(sprintf('The pinned schema has no class named %s.', $class));
        }

        return self::load($class);
    }

    /**
     * What is wrong with the event, against the class its `class_uid` names, or
     * against Base Event when that is not an integer; an empty list when
     * nothing is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $event
     * @return list<string>
     */
    public function errors(array $event): array
    {
        $class = $event['class_uid'] ?? 0;

        if (is_int($class) && !isset($this->schemas[$class])) {
            return [sprintf('class_uid: no pinned class has the uid %d', $class)];
        }

        $schema     = $this->schemas[is_int($class) ? $class : 0];
        $definition = ['attributes' => $schema['attributes'], 'constraints' => $schema['constraints']];
        $metadata   = is_array($event['metadata'] ?? null) ? $event['metadata'] : [];
        $profiles   = is_array($metadata['profiles'] ?? null) ? array_filter($metadata['profiles'], is_string(...)) : [];

        return [...$this->mapErrors($schema, $definition, $event, '', $profiles), ...self::classificationErrors($schema, $event)];
    }

    /**
     * What is wrong with a map against its definition: a missing required
     * attribute, an undeclared one, each member's own errors, and the
     * constraints; a profile the event does not apply declares nothing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  Schema  $schema
     * @param  Definition  $definition
     * @param  array<array-key, mixed>  $value
     * @param  string  $prefix
     * @param  array<array-key, string>  $profiles
     * @return list<string>
     */
    private function mapErrors(array $schema, array $definition, array $value, string $prefix, array $profiles): array
    {
        $applies  = static fn (array $attribute): bool => !isset($attribute['profile']) || in_array($attribute['profile'], $profiles, true);
        $declared = array_filter($definition['attributes'], $applies);
        $errors   = [];

        foreach ($declared as $name => $attribute) {
            if ($attribute['requirement'] !== 'required' || array_key_exists($name, $value)) {
                continue;
            }

            $errors[] = $prefix . $name . ': required attribute is missing';
        }

        foreach ($value as $name => $member) {
            $errors = [...$errors, ...(isset($declared[$name])
                ? $this->memberErrors($schema, $declared[$name], $member, $prefix . $name, $profiles)
                : [$prefix . $name . ': attribute is not declared'])];
        }

        return [...$errors, ...self::constraintErrors($definition['constraints'], $value, $prefix)];
    }

    /**
     * What is wrong with an attribute's value: an array checked member by
     * member when the attribute is one, or the value itself.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  Schema  $schema
     * @param  Attribute  $attribute
     * @param  mixed  $value
     * @param  string  $label
     * @param  array<array-key, string>  $profiles
     * @return list<string>
     */
    private function memberErrors(array $schema, array $attribute, mixed $value, string $label, array $profiles): array
    {
        if (!$attribute['is_array']) {
            return $this->valueErrors($schema, $attribute, $value, $label, $profiles);
        }

        if (!is_array($value) || !array_is_list($value)) {
            return [$label . ': expected an array of ' . $attribute['type']];
        }

        $errors = [];

        foreach ($value as $index => $member) {
            $errors = [...$errors, ...$this->valueErrors($schema, $attribute, $member, $label . '[' . $index . ']', $profiles)];
        }

        return $errors;
    }

    /**
     * What is wrong with one value of an attribute: an object checked against
     * its definition, or a value of the wrong type or outside the enum.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  Schema  $schema
     * @param  Attribute  $attribute
     * @param  mixed  $value
     * @param  string  $label
     * @param  array<array-key, string>  $profiles
     * @return list<string>
     */
    private function valueErrors(array $schema, array $attribute, mixed $value, string $label, array $profiles): array
    {
        $type   = $attribute['type'];
        $object = $schema['objects'][$type] ?? null;

        if ($object !== null && is_array($value) && self::isOfType(self::FREE_OBJECT, $value)) {
            return $this->mapErrors($schema, $object, $value, $label . '.', $profiles);
        }

        $base = $object === null ? $schema['types'][$type] ?? $type : self::FREE_OBJECT;

        if (!self::isOfType($base, $value)) {
            return [sprintf('%s: expected %s, got %s', $label, $type, get_debug_type($value))];
        }

        return self::enumErrors($attribute, $value, $label);
    }

    /**
     * What is wrong with a value of an attribute that has an enum: an integer
     * or a string that is not one of its values.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  Attribute  $attribute
     * @param  mixed  $value
     * @param  string  $label
     * @return list<string>
     */
    private static function enumErrors(array $attribute, mixed $value, string $label): array
    {
        if (!isset($attribute['enum']) || !(is_int($value) || is_string($value)) || array_key_exists($value, $attribute['enum'])) {
            return [];
        }

        return [sprintf('%s: %s is not in its enum', $label, $value)];
    }

    /**
     * What is wrong with a map against the constraints on it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, list<string>>  $constraints
     * @param  array<array-key, mixed>  $value
     * @param  string  $prefix
     * @return list<string>
     */
    private static function constraintErrors(array $constraints, array $value, string $prefix): array
    {
        $errors = [];
        $label  = $prefix === '' ? 'event' : substr($prefix, 0, -1);

        foreach ($constraints as $constraint => $names) {
            $present = count(array_intersect_key($value, array_flip($names)));

            if (($constraint !== 'at_least_one' || $present !== 0) && ($constraint !== 'just_one' || $present === 1)) {
                continue;
            }

            $errors[] = sprintf('%s: %s of %s', $label, $constraint, implode(', ', $names));
        }

        return $errors;
    }

    /**
     * What is wrong with the event's classification: a type that is not its
     * class times 100 plus its activity, or a class that is not its category
     * times 1000 plus the class's own uid.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  Schema  $schema
     * @param  array<array-key, mixed>  $event
     * @return list<string>
     */
    private static function classificationErrors(array $schema, array $event): array
    {
        [$class, $category, $activity, $type] = [$event['class_uid'] ?? null, $event['category_uid'] ?? null, $event['activity_id'] ?? null, $event['type_uid'] ?? null];

        $errors = [];

        if (is_int($class) && is_int($activity) && is_int($type) && $type !== $class * 100 + $activity) {
            $errors[] = sprintf('type_uid: must be class_uid * 100 + activity_id, %d, not %d', $class * 100 + $activity, $type);
        }

        if (is_int($class) && is_int($category) && $class !== $category * 1000 + $schema['uid']) {
            $errors[] = sprintf('class_uid: must be category_uid * 1000 + %d, %d, not %d', $schema['uid'], $category * 1000 + $schema['uid'], $class);
        }

        return $errors;
    }

    /**
     * The class's file, decoded.
     *
     * @param  string  $class
     * @return Schema
     *
     * @throws \JsonException
     */
    private static function load(string $class): array
    {
        /** @var Schema */
        return json_decode((string) file_get_contents(self::ROOT . '/' . $class . '.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Whether the value is of the root type, or is a map when the type is an
     * object.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $type
     * @param  mixed  $value
     * @return bool
     */
    private static function isOfType(string $type, mixed $value): bool
    {
        return match ($type) {
            'string_t'            => is_string($value),
            'integer_t', 'long_t' => is_int($value),
            'float_t'             => is_int($value) || is_float($value),
            'boolean_t'           => is_bool($value),
            'json_t'              => true,
            self::FREE_OBJECT     => is_array($value) && ($value === [] || !array_is_list($value)),
            default               => false,
        };
    }
}
