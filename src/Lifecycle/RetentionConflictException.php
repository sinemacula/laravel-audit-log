<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a retention policy keeps a pair's entries for less than it must
 * preserve them; the prune run stops there.
 *
 * It names the policy's class, never the category or the tenant.
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
