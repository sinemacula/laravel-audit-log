<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions;

use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * What an application declares about one event code: its payload version,
 * category, field rules and OCSF mapper. Immutable: every fluent method returns
 * a new instance.
 *
 * The most specific rule matching a field's path or a prefix of it decides the
 * field, and `retain` never undoes global redaction of secret keys.
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

    /** @var string Pattern of a category slug, the one grammar every category is held to. */
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

        /** The OCSF mapper's class, applied at this version only; `null` for none. */
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
     * The definition of a caller's code, a string or string-backed enum case:
     * version 1, `general`, no rules and unlisted fields dropped.
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
     * The definition an unregistered code takes, retaining every field; also
     * where the package's own codes' definitions start, since `for()` refuses
     * them.
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
     * The definition with the field encrypted under its required owner's key:
     * `KeyOwner::ACTOR`, `KeyOwner::SUBJECT` or a property path holding a
     * reference.
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
     * The definition with a rule for the path; an identical rule changes
     * nothing, and a conflicting or unreachable one is refused whichever came
     * first.
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
     * The definition with every unnamed field handled so; never `encrypt`,
     * which needs an owner.
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
     * The definition classified in OCSF by the mapper class, at this version
     * only; records of other versions project as a Base Event.
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
     * The most specific rule matching a prefix of the path as long as itself,
     * or `null` when none does.
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
     * The first rule, in path order, naming a field beneath the path, or
     * `null`; a rule at or above the path is `ruleFor()`'s.
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
     * @param  array<string>  $paths
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
     * Whether the other definition has exactly this one's rules.
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
     * Refuse a pair of rules where a terminal one may cover the other, naming
     * the longer path first.
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
