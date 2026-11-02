<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldPath;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Applies an event definition's field rules to a record's properties, after key
 * redaction and before the byte budget.
 *
 * The rule is selected first and the value transformed after, so an explicit
 * terminal rule decides its whole subtree, a retained branch keeps walking so
 * that a deeper rule still applies, and the unlisted default gives way wherever
 * a rule names something beneath it. A structural ancestor left empty is
 * removed and not counted, since its removed children were, while a retained
 * container left empty stays, because it was retained. A list reindexes what
 * survives, and a map keeps its keys and their order.
 *
 * Only a retained string is cut, at 1024 bytes, and a string is cut the same
 * way before it is sealed. Anything else is sealed as its canonical encoding,
 * which cutting would leave undecodable, so one of more than 1024 bytes is
 * removed without reaching the encrypter. A pseudonym covers the complete
 * value, and no marker, pseudonym or envelope is ever cut. A value key
 * redaction replaced stays the marker under every handling but `DROP`, because
 * hashing or encrypting the marker would look like evidence of a value.
 *
 * The owners of encrypted fields are read before any field is handled, once per
 * rule, so a rule on the owner's own path cannot hide it. An encrypted field
 * with no owner, too long to seal, or that cannot be sealed, is removed and
 * never stored in plaintext. Every removal is logged under its masked path,
 * never a value or a dynamic key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FieldPolicy
{
    /** @var int Longest string a retained value or a plaintext keeps, in bytes. */
    public const int STRING_MAX_BYTES = 1024;

    /** @var int How many keys a map holding a reference has: `type` and `id`. */
    private const int REFERENCE_PARTS = 2;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The values with the definition's rules applied, and each removal logged.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public static function apply(
        #[\SensitiveParameter]
        array $values,
        EventDefinition $definition,
        ?Reference $actor,
        ?Reference $subject,
        IdentifierHasher $hasher,
        EnvelopeSealer $sealer,
        OmissionLog $omissions,
    ): array {
        $owners = self::owners($values, $definition, $actor, $subject);

        $handle = static function (
            #[\SensitiveParameter]
            mixed $value,
            #[\SensitiveParameter]
            array $path,
            ?FieldRule $rule,
        ) use (
            $definition,
            $owners,
            $hasher,
            $sealer,
            $omissions,
        ): ?array {
            $owner = $rule === null ? null : ($owners[$rule->path] ?? null);
            $kept  = self::handled($value, $rule->handling ?? $definition->unlisted, $owner, $hasher, $sealer);

            if ($kept === null) {
                $omissions->add(PathMasker::property($path, $definition));
            }

            return $kept;
        };

        return self::walk($values, [], $definition, $handle);
    }

    /**
     * The values with every plain string cut to 1024 bytes, at every depth,
     * with their keys and order kept.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public static function capped(#[\SensitiveParameter] array $values): array
    {
        foreach ($values as $key => $value) {
            $values[$key] = is_array($value) ? self::capped($value) : self::cut($value);
        }

        return $values;
    }

    /**
     * The owner of each encrypted field's rule, by the rule's path, or `null`
     * for a rule whose owner is absent.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @return array<array-key, ?\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function owners(#[\SensitiveParameter] array $values, EventDefinition $definition, ?Reference $actor, ?Reference $subject): array
    {
        $owners = [];

        foreach ($definition->rules as $rule) {
            if ($rule->handling !== FieldHandling::ENCRYPT) {
                continue;
            }

            $owners[$rule->path] = self::ownerOf($rule->owner, $values, $actor, $subject);
        }

        return $owners;
    }

    /**
     * The party an encrypted field's rule names: the record's actor or subject,
     * or the reference held at a property's path.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string|null  $owner
     * @param  array<array-key, mixed>  $values
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function ownerOf(KeyOwner|string|null $owner, #[\SensitiveParameter] array $values, ?Reference $actor, ?Reference $subject): ?Reference
    {
        if (is_string($owner)) {
            return self::referenceAt($values, FieldPath::parse($owner));
        }

        return $owner === KeyOwner::ACTOR ? $actor : $subject;
    }

    /**
     * The reference held at the segments of a property's path, or `null` when
     * the path is absent or holds anything else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  non-empty-list<string>  $segments
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function referenceAt(#[\SensitiveParameter] array $values, array $segments): ?Reference
    {
        $node = $values;

        foreach ($segments as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return null;
            }

            $node = $node[$segment];
        }

        return is_array($node) ? self::reference($node) : null;
    }

    /**
     * The reference a map holds: exactly the keys `type` and `id`, in any
     * order, a string and a string or integer that `Reference` accepts. Either
     * part holding the marker is no owner, since a field is never keyed on a
     * redacted value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $node
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function reference(#[\SensitiveParameter] array $node): ?Reference
    {
        $type = $node['type'] ?? null;
        $id   = $node['id']   ?? null;

        if (count($node) !== self::REFERENCE_PARTS || !is_string($type) || !(is_string($id) || is_int($id)) || in_array(Redactor::MARKER, [$type, $id], true)) {
            return null;
        }

        try {
            return Reference::of($type, $id);
        } catch (\InvalidArgumentException) {
            // A map that holds no valid reference is simply no owner, so the
            // field it would have keyed is dropped and diagnosed
            return null;
        }
    }

    /**
     * The node's survivors: a list reindexed, and a map with its keys and their
     * order kept.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $node
     * @param  list<int|string>  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  \Closure(mixed, list<int|string>, ?\SineMacula\Laravel\AuditLog\Definitions\FieldRule): ?array{0: mixed}  $handle
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function walk(#[\SensitiveParameter] array $node, #[\SensitiveParameter] array $path, EventDefinition $definition, \Closure $handle): array
    {
        $isList = array_is_list($node);

        foreach ($node as $key => $value) {
            $kept = self::selected($value, [...$path, $key], $definition, $handle);

            if ($kept === null) {
                unset($node[$key]);

                continue;
            }

            $node[$key] = $kept[0];
        }

        return $isList ? array_values($node) : $node;
    }

    /**
     * What is kept of the value at the path, wrapped so that a kept `null` can
     * be told from a removal, which is `null`: an explicit terminal rule
     * handles the whole value, a retaining rule retains it, a non-empty
     * container with a rule beneath it is walked and removed when nothing
     * survives, and anything else takes the unlisted default.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  list<int|string>  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  \Closure(mixed, list<int|string>, ?\SineMacula\Laravel\AuditLog\Definitions\FieldRule): ?array{0: mixed}  $handle
     * @return ?array{0: mixed}
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function selected(#[\SensitiveParameter] mixed $value, #[\SensitiveParameter] array $path, EventDefinition $definition, \Closure $handle): ?array
    {
        $rule = $definition->ruleFor($path);

        if ($rule !== null) {
            return $rule->handling->isTerminal() ? $handle($value, $path, $rule) : [self::retained($value, $path, $definition, $handle)];
        }

        if (is_array($value) && $value !== [] && $definition->ruleBeneath($path) !== null) {
            $survivors = self::walk($value, $path, $definition, $handle);

            return $survivors === [] ? null : [$survivors];
        }

        return $definition->unlisted === FieldHandling::RETAIN ? [self::retained($value, $path, $definition, $handle)] : $handle($value, $path, null);
    }

    /**
     * The value as it is retained: a container walked, so a deeper rule still
     * applies, a string cut, and anything else as it is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  list<int|string>  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  \Closure(mixed, list<int|string>, ?\SineMacula\Laravel\AuditLog\Definitions\FieldRule): ?array{0: mixed}  $handle
     * @return mixed
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function retained(#[\SensitiveParameter] mixed $value, #[\SensitiveParameter] array $path, EventDefinition $definition, \Closure $handle): mixed
    {
        return is_array($value) ? self::walk($value, $path, $definition, $handle) : self::cut($value);
    }

    /**
     * The value with a terminal handling applied, wrapped, or `null` when it is
     * removed. A value already the marker stays the marker unless it is
     * dropped.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
     * @return ?array{0: mixed}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function handled(
        #[\SensitiveParameter]
        mixed $value,
        FieldHandling $handling,
        #[\SensitiveParameter]
        ?Reference $owner,
        IdentifierHasher $hasher,
        EnvelopeSealer $sealer,
    ): ?array {
        if ($handling === FieldHandling::DROP) {
            return null;
        }

        if ($handling === FieldHandling::REDACT || $value === Redactor::MARKER) {
            return [Redactor::MARKER];
        }

        return $handling === FieldHandling::PSEUDONYMISE ? [self::pseudonym($value, $hasher)] : self::sealed($value, $owner, $sealer);
    }

    /**
     * The hash of the complete value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function pseudonym(#[\SensitiveParameter] mixed $value, IdentifierHasher $hasher): string
    {
        return $hasher->field(self::hashable($value));
    }

    /**
     * The value, when it can be hashed. A normalised value is never a float or
     * an object, so one here is a programming error and fails the write, naming
     * only its type.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return array<array-key, mixed>|bool|int|string|null
     *
     * @throws \UnexpectedValueException
     */
    private static function hashable(#[\SensitiveParameter] mixed $value): array|bool|int|string|null
    {
        return match (true) {
            $value === null,
            is_array($value),
            is_bool($value),
            is_int($value),
            is_string($value) => $value,
            default           => throw new \UnexpectedValueException(sprintf('A value of type %s cannot be pseudonymised.', get_debug_type($value))),
        };
    }

    /**
     * The value's envelope, wrapped, or `null` when it has no owner or cannot
     * be sealed. A string is cut to 1024 bytes before it reaches the encrypter.
     * Anything else is sealed as its canonical encoding, and an encoding of
     * more than 1024 bytes never reaches it, since a cut one could not be
     * decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
     * @return ?array{0: array{v: int, k: string, c: string}}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function sealed(#[\SensitiveParameter] mixed $value, #[\SensitiveParameter] ?Reference $owner, EnvelopeSealer $sealer): ?array
    {
        if ($owner === null) {
            return null;
        }

        $plaintext = is_string($value) ? TextSanitizer::cut($value, self::STRING_MAX_BYTES) : CanonicalEncoder::encode($value);
        $envelope  = strlen($plaintext) > self::STRING_MAX_BYTES ? null : $sealer->seal($owner, $plaintext);

        return $envelope === null ? null : [$envelope];
    }

    /**
     * The value with a string cut to 1024 bytes, and anything else as it is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    private static function cut(#[\SensitiveParameter] mixed $value): mixed
    {
        return is_string($value) ? TextSanitizer::cut($value, self::STRING_MAX_BYTES) : $value;
    }
}
