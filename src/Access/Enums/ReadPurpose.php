<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Access\Enums;

/**
 * What a viewer reads the trail for. The access policy is asked for a scope per
 * purpose on every read, so a viewer may page through entries it may never
 * export, and the purpose is kept on the record of the read.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ReadPurpose: string
{
    // A page of entries, shown to the viewer
    case READ = 'read';

    // The number of entries, with none of them shown
    case COUNT = 'count';

    // Every entry, written to a file as evidence
    case EXPORT = 'export';

    // An export, checked against the entry that journalled it
    case VERIFY = 'verify';
}
