<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Why a line of an import file was rejected rather than imported. A rejected
 * line is counted under its reason and writes nothing; the import goes on with
 * the next line.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ImportRejection: string
{
    // The line is not a JSON object
    case MALFORMED_JSON = 'malformed_json';

    // The line names no format, or a format the import does not read
    case UNSUPPORTED_FORMAT = 'unsupported_format';

    // The line is of a version of its format the import does not read
    case UNSUPPORTED_VERSION = 'unsupported_version';

    // The line holds a field its format does not have
    case UNKNOWN_FIELD = 'unknown_field';

    // The line lacks a field its format requires
    case MISSING_FIELD = 'missing_field';

    // A field of the line is not of its format's type or grammar, or the record
    // refuses it
    case INVALID_FIELD = 'invalid_field';

    // The line's code is under the prefix reserved for the package's own codes
    case RESERVED_CODE = 'reserved_code';

    // The line's code is not registered, and unregistered codes are refused
    case UNREGISTERED_CODE = 'unregistered_code';

    // The line's occurrence time is not an instant in the package's form
    case INVALID_TIME = 'invalid_time';

    // The line claims to have happened further ahead of the clock than the skew
    // allows
    case FUTURE_TIME = 'future_time';

    // The line's source is this installation, whose own records come back
    // through replay, never as an import
    case OWN_SOURCE = 'own_source';

    // The line names a source other than the import's
    case SOURCE_MISMATCH = 'source_mismatch';

    // The line is longer than the longest line an import reads
    case OVERSIZED_LINE = 'oversized_line';
}
