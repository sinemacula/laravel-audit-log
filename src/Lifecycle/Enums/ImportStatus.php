<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Where an import batch stands: still running, or finished in one of four ways.
 * A batch is written `running` before its first entry, and moves once to a
 * final status, which it never leaves.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ImportStatus: string
{
    // The import is writing the batch's lines
    case RUNNING = 'running';

    // Every line read was imported or was a duplicate of one already imported
    case COMPLETE = 'complete';

    // The import reached the end of the file, but some lines were rejected or
    // conflicted with what was already imported
    case PARTIAL = 'partial';

    // The import stopped on a failure before the end of the file
    case FAILED = 'failed';

    // The batch was closed by hand while it was still running, after the import
    // that ran it stopped
    case INTERRUPTED = 'interrupted';

    /**
     * Whether the status is final: every status but `running` is.
     *
     * @return bool
     */
    public function isFinal(): bool
    {
        return $this !== self::RUNNING;
    }
}
