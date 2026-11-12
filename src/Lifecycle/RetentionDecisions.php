<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The decisions of one prune: each pair is asked of the policy once and kept
 * for the run, so it never gets two cut-offs.
 *
 * A malformed answer is refused naming the policy's class and method, never the
 * category or the tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RetentionDecisions
{
    /** @var int Longest version a policy may give, in characters. */
    private const int VERSION_MAX_CHARACTERS = 64;

    /** @var int Seconds in a UTC day, which has no daylight saving to shorten or lengthen it. */
    private const int SECONDS_PER_DAY = 86400;

    /** @var string The refusal of a malformed answer, by the policy's class, the method and what the answer must be. */
    private const string MALFORMED = 'The retention policy `%s` answered `%s()` with %s; pruning refuses it.';

    /** @var string What a retention must be. */
    private const string RETENTION_GRAMMAR = 'something other than 1 to 36500 days or null';

    /** @var string What a preservation must be. */
    private const string PRESERVATION_GRAMMAR = 'something other than 1 to 36500 days, PHP_INT_MAX or null';

    /** @var string What a version must be. */
    private const string VERSION_GRAMMAR = 'something other than 1 to 64 characters of clean text';

    /** @var \DateTimeImmutable The run's midnight, in UTC. */
    private readonly \DateTimeImmutable $midnight;

    /** @var array<string, \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision> The decisions made, by their pair, in the order they were first made. */
    private array $decisions = [];

    /** @var ?string The policy's version, once it has been checked. */
    private ?string $version = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy  $policy
     * @param  \DateTimeInterface  $midnight
     */
    public function __construct(

        /** The policy the decisions are asked of. */
        private readonly RetentionPolicy $policy,

        // Not promoted: kept as the UTC midnight of its day
        \DateTimeInterface $midnight,
    ) {
        $this->midnight = \DateTimeImmutable::createFromInterface($midnight)
            ->setTimezone(new \DateTimeZone('UTC'))
            ->setTime(0, 0);
    }

    /**
     * The pair's decision, made from the policy's checked answers the first
     * time it is asked for.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     */
    public function for(string $category, ?Reference $tenant): RetentionDecision
    {
        $pair = CanonicalEncoder::encode([$category, $tenant?->type, $tenant?->id]);

        if (isset($this->decisions[$pair])) {
            return $this->decisions[$pair];
        }

        $retainDays   = $this->retention($this->policy->retainFor($category, $tenant));
        $preserveDays = $this->preservation($this->policy->preserveFor($category, $tenant));

        $this->refuseAConflictOf($retainDays, $preserveDays);

        return $this->decisions[$pair] = new RetentionDecision($category, $tenant, $retainDays, $preserveDays, $this->cutoff($retainDays));
    }

    /**
     * Every decision made so far, in the order each pair was first asked for.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision>
     */
    public function all(): array
    {
        return array_values($this->decisions);
    }

    /**
     * The policy's version, asked and checked once for the run.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function version(): string
    {
        if ($this->version !== null) {
            return $this->version;
        }

        $version = $this->policy->version();

        if ($version === '' || mb_strlen($version, 'UTF-8') > self::VERSION_MAX_CHARACTERS || !TextSanitizer::isClean($version)) {
            throw $this->malformed('version', self::VERSION_GRAMMAR);
        }

        return $this->version = $version;
    }

    /**
     * The run's midnight, as an instant in the package's form.
     *
     * @return string
     */
    public function midnight(): string
    {
        return StoredTime::format($this->midnight);
    }

    /**
     * The policy's retention, refused unless it is 1 to 36500 days or `null`.
     *
     * @param  ?int  $days
     * @return ?int
     *
     * @throws \UnexpectedValueException
     */
    private function retention(?int $days): ?int
    {
        if ($days !== null && ($days < 1 || $days > RetentionSettings::MAX_DAYS)) {
            throw $this->malformed('retainFor', self::RETENTION_GRAMMAR);
        }

        return $days;
    }

    /**
     * The policy's preservation, refused unless 1 to 36500 days, `PHP_INT_MAX`
     * or `null`.
     *
     * @param  ?int  $days
     * @return ?int
     *
     * @throws \UnexpectedValueException
     */
    private function preservation(?int $days): ?int
    {
        if ($days !== null && $days !== PHP_INT_MAX && ($days < 1 || $days > RetentionSettings::MAX_DAYS)) {
            throw $this->malformed('preserveFor', self::PRESERVATION_GRAMMAR);
        }

        return $days;
    }

    /**
     * Refuse a finite retention shorter than the preservation, forever
     * included.
     *
     * @param  ?int  $retainDays
     * @param  ?int  $preserveDays
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     */
    private function refuseAConflictOf(?int $retainDays, ?int $preserveDays): void
    {
        if ($retainDays !== null && $preserveDays !== null && $retainDays < $preserveDays) {
            throw RetentionConflictException::forPolicy($this->policy::class);
        }
    }

    /**
     * The run's midnight less the days, or `null` for a pair kept forever.
     *
     * @param  ?int  $days
     * @return ?string
     */
    private function cutoff(?int $days): ?string
    {
        return $days === null ? null : StoredTime::format($this->midnight->setTimestamp($this->midnight->getTimestamp() - $days * self::SECONDS_PER_DAY));
    }

    /**
     * The refusal of the policy's answer to the method.
     *
     * @param  string  $method
     * @param  string  $grammar
     * @return \UnexpectedValueException
     */
    private function malformed(string $method, string $grammar): \UnexpectedValueException
    {
        return new \UnexpectedValueException(sprintf(self::MALFORMED, $this->policy::class, $method, $grammar));
    }
}
