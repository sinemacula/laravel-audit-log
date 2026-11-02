<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime\Enums;

use SineMacula\Laravel\AuditLog\Records\Enums\Origin;

/**
 * What an execution frame stands for: the HTTP request, an Artisan command or a
 * queued job the current code is running in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum FrameKind: string
{
    // The HTTP request being served
    case HTTP = 'http';

    // An Artisan command, from the console or called in-process
    case COMMAND = 'command';

    // A queued job, on a worker or the sync queue
    case JOB = 'job';

    /**
     * The origin a record made while this kind of frame is innermost carries.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Enums\Origin
     */
    public function origin(): Origin
    {
        return match ($this) {
            self::HTTP    => Origin::HTTP,
            self::COMMAND => Origin::CONSOLE,
            self::JOB     => Origin::QUEUE,
        };
    }
}
