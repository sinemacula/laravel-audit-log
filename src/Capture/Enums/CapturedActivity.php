<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * The codes the package records for Laravel's authentication and authorisation
 * events, defined at boot, so a conflicting definition is refused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CapturedActivity: string implements DefinesAuditEvents
{
    // A user signed in
    case SIGNED_IN = 'authentication.signed_in';

    // A user's session was restored from a remember-me cookie
    case SESSION_RESTORED = 'authentication.session_restored';

    // A sign-in was attempted and failed
    case SIGN_IN_FAILED = 'authentication.sign_in_failed';

    // A user signed out
    case SIGNED_OUT = 'authentication.signed_out';

    // A user signed out of their other devices
    case SIGNED_OUT_OTHER_DEVICES = 'authentication.signed_out_other_devices';

    // Sign-in attempts were refused after too many failures
    case LOCKED_OUT = 'authentication.locked_out';

    // An account was registered
    case REGISTERED = 'account.registered';

    // An account's email address was verified
    case EMAIL_VERIFIED = 'account.email_verified';

    // An account's password was reset
    case PASSWORD_RESET = 'account.password_reset';

    // A link to reset an account's password was sent
    case PASSWORD_RESET_REQUESTED = 'account.password_reset_requested';

    // The gate denied an ability
    case GATE_DENIED = 'authorization.gate_denied';

    /** @var string The category every package code is stored under. */
    private const string CATEGORY = 'security';

    /**
     * The case's definition: version 1, `security`, and every field dropped but
     * `remember` for a sign-in or restored session and the ability and its
     * arguments for a Gate denial.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        $definition = EventDefinition::for($this)->category(self::CATEGORY);

        return match ($this) {
            self::SIGNED_IN,
            self::SESSION_RESTORED => $definition->retain('remember'),
            self::GATE_DENIED      => $definition->retain('ability', 'arguments', 'argument_count'),
            default                => $definition,
        };
    }
}
