<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Where an import batch stands; a batch starts `running` and moves once to a
 * final status.
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

    // The import reached the end of the file with rejected or conflicting lines
    case PARTIAL = 'partial';

    // The import stopped on a failure before the end of the file
    case FAILED = 'failed';

    // The batch was closed by hand after the import that ran it stopped
    case INTERRUPTED = 'interrupted';

    /**
     * Whether the status is final.
     *
     * @return bool
     */
    public function isFinal(): bool
    {
        return $this !== self::RUNNING;
    }
}
