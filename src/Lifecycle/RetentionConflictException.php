<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a retention policy keeps the entries of a category and tenant
 * pair for a finite time shorter than it says they must be preserved, so a
 * prune would delete what must stay readable. The run stops there, and the
 * chunks it already committed stand.
 *
 * It names the policy's class and never the category or the tenant, so nothing
 * it holds can reach an entry.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RetentionConflictException extends \UnexpectedValueException
{
    /** @var string The refusal, by the policy's class. */
    private const string MESSAGE = 'The retention policy `%s` retains a category for less than it must be preserved; pruning refuses it.';

    /**
     * The exception for the policy of the class.
     *
     * @param  string  $policyClass
     * @return self
     */
    public static function forPolicy(string $policyClass): self
    {
        return new self(sprintf(self::MESSAGE, $policyClass));
    }
}
