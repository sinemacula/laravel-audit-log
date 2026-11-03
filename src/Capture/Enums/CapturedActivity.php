<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * The codes the package records when it captures Laravel's own authentication
 * and authorisation events, each defined for the security category.
 *
 * The package defines these at boot, so an application or an integration that
 * defines one of them differently is refused then; an integration records its
 * own activity under codes it defines. Every definition is version 1, in the
 * `security` category, and drops every field it does not list: a sign-in keeps
 * only whether it was remembered, a gate denial only the ability and its
 * arguments, and every other code keeps no property at all.
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
     * The definition of this case's event code: version 1, the `security`
     * category and every field it does not list dropped, keeping `remember` for
     * a sign-in, the ability, its arguments and their count for a gate denial,
     * and nothing for any other code.
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
