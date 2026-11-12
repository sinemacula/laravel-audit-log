<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Enums;

/**
 * Where the activity a record describes ran; only an import of unknown origin
 * has none.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Origin: string
{
    // An HTTP request
    case HTTP = 'http';

    // An Artisan command or the scheduler
    case CONSOLE = 'console';

    // A queued job
    case QUEUE = 'queue';
}
