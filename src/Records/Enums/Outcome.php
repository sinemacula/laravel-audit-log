<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Enums;

/**
 * How the activity a record describes ended: it succeeded, it failed, or a
 * policy denied it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Outcome: string
{
    // The activity happened as asked
    case SUCCESS = 'success';

    // The activity was attempted and did not complete
    case FAILURE = 'failure';

    // A policy refused the activity before it was attempted
    case DENIED = 'denied';
}
