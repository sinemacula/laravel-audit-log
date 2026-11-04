<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * What an application declares about one event code: the version of its payload
 * contract, the category stored on every row, the rules for the fields of its
 * properties, with how a field no rule names is handled, and the mapper, if
 * any, that classifies its records in OCSF.
 *
 * A definition is immutable: every fluent method returns a new instance and
 * leaves the original as it was. A registered code drops the fields no rule
 * names unless `unlisted()` says otherwise, and an unregistered code takes the
 * permissive default, which retains them. The most specific rule matching a
 * field's path, or a prefix of it, decides the field: a rule on a map covers
 * everything beneath it. A rule that could never apply, beneath a rule that
 * decides its whole branch, is refused whichever is added first, and so is a
 * second rule for a path. Rules are kept in path order, so definitions built in
 * any order are equal.
 *
 * Applying the rules to a payload is the redaction pipeline's work: global
 * redaction of secret keys comes first, and `retain` never undoes it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EventDefinition
{
    /** @var int Least version of a payload contract. */
    public const int MIN_VERSION = 1;

    /** @var int Greatest version of a payload contract: PostgreSQL's signed smallint. */
    public const int MAX_VERSION = 32767;

    /** @var string Category of a definition that names none. */
    public const string DEFAULT_CATEGORY = 'general';

    /** @var string Pattern of a category slug: a lower-case letter, then up to 63 lower-case letters, digits or underscores; the one grammar every category is held to. */
    public const string CATEGORY_PATTERN = '/\A[a-z][a-z0-9_]{0,63}\z/';

    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  int  $version
     * @param  string  $category
     * @param  array<string, \SineMacula\Laravel\AuditLog\Definitions\FieldRule>  $rules
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $unlisted
     * @param  ?class-string<\SineMacula\Laravel\AuditLog\Contracts\OcsfMapper>  $ocsfMapper
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The event code the definition is for. */
        public string $code,

        /** The payload contract's version, 1 to 32767. */
        public int $version,

        /** The category slug, stored on every row. */
        public string $category,

        /** The field rules, by path, in path order. */
        public array $rules,

        /** How a field no rule names is handled. */
        public FieldHandling $unlisted,

        /** The class of the mapper that classifies the code's records in OCSF, at this version only; `null` for none. */
        public ?string $ocsfMapper = null,
    ) {
        if ($version < self::MIN_VERSION || $version > self::MAX_VERSION) {
            throw new \InvalidArgumentException(sprintf('An event definition\'s version must be from %d to %d.', self::MIN_VERSION, self::MAX_VERSION));
        }

        if (preg_match(self::CATEGORY_PATTERN, $category) !== 1) {
            throw new \InvalidArgumentException('An event definition\'s category must be 1 to 64 lower-case letters, digits or underscores, starting with a letter.');
        }

        if ($unlisted === FieldHandling::ENCRYPT) {
            throw new \InvalidArgumentException('Unlisted fields cannot be encrypted, because an encrypted field names its owner.');
        }
    }

    /**
     * The definition of a caller's code, given as a string or as a
     * string-backed enum case: version 1, the `general` category, no rules, and
     * every unlisted field dropped.
     *
     * @param  \BackedEnum|string  $code
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function for(\BackedEnum|string $code): self
    {
        return new self(EventCode::of($code)->value, self::MIN_VERSION, self::DEFAULT_CATEGORY, [], FieldHandling::DROP, null);
    }

    /**
     * The definition an unregistered code takes: version 1, the `general`
     * category, no rules, and every field retained. The code is already
     * validated, so this is also where the definition of one of the package's
     * own codes starts, which `for()` refuses.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function permissive(EventCode $code): self
    {
        return new self($code->value, self::MIN_VERSION, self::DEFAULT_CATEGORY, [], FieldHandling::RETAIN, null);
    }

    /**
     * The definition with the version of its payload contract, from 1 to 32767.
     *
     * @param  int  $version
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function version(int $version): self
    {
        return new self($this->code, $version, $this->category, $this->rules, $this->unlisted, $this->ocsfMapper);
    }

    /**
     * The definition in the category: a slug of 1 to 64 lower-case letters,
     * digits or underscores, starting with a letter.
     *
     * @param  string  $category
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function category(string $category): self
    {
        return new self($this->code, $this->version, $category, $this->rules, $this->unlisted, $this->ocsfMapper);
    }

    /**
     * The definition with the fields at the paths kept as captured.
     *
     * @param  string  ...$paths
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function retain(string ...$paths): self
    {
        return $this->withRules(FieldHandling::RETAIN, $paths);
    }

    /**
     * The definition with the fields at the paths stored as `[REDACTED]`.
     *
     * @param  string  ...$paths
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function redact(string ...$paths): self
    {
        return $this->withRules(FieldHandling::REDACT, $paths);
    }

    /**
     * The definition with the fields at the paths stored as keyed,
     * fingerprinted hashes.
     *
     * @param  string  ...$paths
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function pseudonymise(string ...$paths): self
    {
        return $this->withRules(FieldHandling::PSEUDONYMISE, $paths);
    }

    /**
     * The definition with the field at the path encrypted under its owner's
     * key: `KeyOwner::ACTOR`, `KeyOwner::SUBJECT` or the path of a property
     * holding a reference. The owner is required.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string|null  $owner
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function encrypt(string $path, KeyOwner|string|null $owner = null): self
    {
        return $this->rule($path, FieldHandling::ENCRYPT, $owner);
    }

    /**
     * The definition with the fields at the paths not stored.
     *
     * @param  string  ...$paths
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function drop(string ...$paths): self
    {
        return $this->withRules(FieldHandling::DROP, $paths);
    }

    /**
     * The definition with a rule for the path. Repeating an identical rule
     * changes nothing; a different rule for a path that has one, and a rule
     * that could never apply because one that decides its whole branch may
     * cover it, are refused, whichever of the two is added first.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner|string|null  $owner
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function rule(string $path, FieldHandling $handling, KeyOwner|string|null $owner = null): self
    {
        $rule  = new FieldRule($path, $handling, $owner);
        $rules = $this->rules;

        if (isset($rules[$path]) && !$rules[$path]->equals($rule)) {
            throw new \InvalidArgumentException(sprintf('The path `%s` already has a rule.', $path));
        }

        foreach ($rules as $existing) {
            self::refuseUnreachable($rule, $existing);
        }

        $rules[$path] = $rule;

        ksort($rules, SORT_STRING);

        return new self($this->code, $this->version, $this->category, $rules, $this->unlisted, $this->ocsfMapper);
    }

    /**
     * The definition with every field no rule names handled so: any handling
     * but `encrypt`, since an encrypted field names its owner.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function unlisted(FieldHandling $handling): self
    {
        return new self($this->code, $this->version, $this->category, $this->rules, $handling, $this->ocsfMapper);
    }

    /**
     * The definition with its records classified in OCSF by the mapper, a class
     * implementing `OcsfMapper` that the formatter makes from the container.
     * The mapping applies only to records of the definition's version: a record
     * of any other version is projected as a Base Event. A definition keeps the
     * class name, never an instance.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\OcsfMapper>  $mapper
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function ocsf(string $mapper): self
    {
        if (!class_exists($mapper) || !is_subclass_of($mapper, OcsfMapper::class)) {
            throw new \InvalidArgumentException(sprintf('`%s` is not a class implementing `OcsfMapper`.', $mapper));
        }

        return new self($this->code, $this->version, $this->category, $this->rules, $this->unlisted, $mapper);
    }

    /**
     * Whether the other definition has the same code, version, category,
     * unlisted handling, OCSF mapper and rules.
     *
     * @param  self  $other
     * @return bool
     */
    public function equals(self $other): bool
    {
        $mine   = [$this->code, $this->version, $this->category, $this->unlisted, $this->ocsfMapper];
        $theirs = [$other->code, $other->version, $other->category, $other->unlisted, $other->ocsfMapper];

        return $mine === $theirs && $this->hasEqualRules($other);
    }

    /**
     * The rule that decides the field at the concrete path: of the rules
     * matching a prefix of it as long as themselves, the most specific, or
     * `null` when none does.
     *
     * @param  list<int|string>  $path
     * @return ?\SineMacula\Laravel\AuditLog\Definitions\FieldRule
     *
     * @internal
     */
    public function ruleFor(#[\SensitiveParameter] array $path): ?FieldRule
    {
        $winner = null;

        foreach ($this->rules as $rule) {
            if (!FieldPath::matches($rule->segments, array_slice($path, 0, count($rule->segments)))) {
                continue;
            }

            if ($winner !== null && FieldPath::compare($rule->segments, $winner->segments) <= 0) {
                continue;
            }

            $winner = $rule;
        }

        return $winner;
    }

    /**
     * The first rule, in path order, that names a field beneath the concrete
     * path: it has more segments than the path and its leading segments match
     * it, or `null` when no rule does. A rule at or above the path decides the
     * path itself, and is the answer of `ruleFor()`, not of this.
     *
     * @param  list<int|string>  $path
     * @return ?\SineMacula\Laravel\AuditLog\Definitions\FieldRule
     *
     * @internal
     */
    public function ruleBeneath(#[\SensitiveParameter] array $path): ?FieldRule
    {
        $length = count($path);

        foreach ($this->rules as $rule) {
            if (count($rule->segments) > $length && FieldPath::matches(array_slice($rule->segments, 0, $length), $path)) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * How the field at the concrete path is handled: by the rule that decides
     * it, or as unlisted fields are when none does.
     *
     * @param  list<int|string>  $path
     * @return \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling
     *
     * @internal
     */
    public function handlingFor(#[\SensitiveParameter] array $path): FieldHandling
    {
        return $this->ruleFor($path)->handling ?? $this->unlisted;
    }

    /**
     * The definition with a rule of the handling for each of the paths.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @param  list<string>  $paths
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    private function withRules(FieldHandling $handling, array $paths): self
    {
        $definition = new self($this->code, $this->version, $this->category, $this->rules, $this->unlisted, $this->ocsfMapper);

        foreach ($paths as $path) {
            $definition = $definition->rule($path, $handling);
        }

        return $definition;
    }

    /**
     * Whether the other definition has a rule equal to each of this one's, and
     * no other.
     *
     * @param  self  $other
     * @return bool
     */
    private function hasEqualRules(self $other): bool
    {
        if (count($this->rules) !== count($other->rules)) {
            return false;
        }

        foreach ($this->rules as $path => $rule) {
            if (!isset($other->rules[$path]) || !$rule->equals($other->rules[$path])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Refuse a pair of rules where one decides its whole branch and may cover
     * the other, naming the longer path first.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\FieldRule  $added
     * @param  \SineMacula\Laravel\AuditLog\Definitions\FieldRule  $existing
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseUnreachable(FieldRule $added, FieldRule $existing): void
    {
        foreach ([[$added, $existing], [$existing, $added]] as [$descendant, $ancestor]) {
            if ($ancestor->handling->isTerminal() && FieldPath::mayBeBeneath($descendant->segments, $ancestor->segments)) {
                throw new \InvalidArgumentException(sprintf('The rule for `%s` is unreachable beneath the rule for `%s`.', $descendant->path, $ancestor->path));
            }
        }
    }
}
