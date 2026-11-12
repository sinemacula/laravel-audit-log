<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * A failed step of an export's verification, in the order the chain checks
 * them; it names the step, never a value, so it is safe to log.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ExportFinding: string
{
    // The bundle beside the file is missing or not one this release writes
    case BUNDLE_MALFORMED = 'bundle_malformed';

    // The export entry is not stored, or the viewer may not see it
    case ENTRY_MISSING = 'entry_missing';

    // The export entry's key, integrity version or row cannot be verified
    case ENTRY_UNVERIFIABLE = 'entry_unverifiable';

    // The export entry's signature does not match its content
    case ENTRY_TAMPERED = 'entry_tampered';

    // The entry found is not the export journal the bundle names
    case ENTRY_SWAPPED = 'entry_swapped';

    // The descriptor the entry signed is not the bundle's, or not an export's
    case DESCRIPTOR_MISMATCH = 'descriptor_mismatch';

    // The artifact the descriptor names is not stored
    case ARTIFACT_MISSING = 'artifact_missing';

    // The artifact's id or entry is not the one its descriptor signed
    case ARTIFACT_SWAPPED = 'artifact_swapped';

    // The artifact is stored as another kind than its descriptor signed
    case ARTIFACT_WRONG_KIND = 'artifact_wrong_kind';

    // The artifact's count or digest is not the one its descriptor signed
    case ARTIFACT_MISMATCH = 'artifact_mismatch';

    // The artifact's members cannot be decrypted with the application's keys
    case ARTIFACT_UNDECRYPTABLE = 'artifact_undecryptable';

    // The artifact's members are no canonical export manifest
    case ARTIFACT_MALFORMED = 'artifact_malformed';

    // The artifact's manifest is canonical but not the one signed
    case ARTIFACT_TAMPERED = 'artifact_tampered';

    // The manifest the bundle carries is not the one the journal holds
    case MANIFEST_MISMATCH = 'manifest_mismatch';

    // The file's digest is not the one its manifest holds
    case FILE_MISMATCH = 'file_mismatch';

    // The file's lines, ids or end positions are not its manifest's
    case MEMBERSHIP_MISMATCH = 'membership_mismatch';

    // A line of the file is not a line of its format, or names no id
    case LINE_MALFORMED = 'line_malformed';

    // An NDJSON line's key, integrity version or columns cannot be verified
    case LINE_UNVERIFIABLE = 'line_unverifiable';

    // A line's signature does not match its content
    case LINE_TAMPERED = 'line_tampered';

    /**
     * The export finding for an artifact finding; any other is refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArtifactFinding(Finding $finding): self
    {
        return match ($finding) {
            Finding::MANIFEST_MISSING    => self::ARTIFACT_MISSING,
            Finding::MANIFEST_SWAPPED    => self::ARTIFACT_SWAPPED,
            Finding::MANIFEST_WRONG_KIND => self::ARTIFACT_WRONG_KIND,
            Finding::MANIFEST_MISMATCH   => self::ARTIFACT_MISMATCH,
            Finding::MANIFEST_UNREADABLE => self::ARTIFACT_UNDECRYPTABLE,
            Finding::MANIFEST_MALFORMED  => self::ARTIFACT_MALFORMED,
            Finding::MANIFEST_TAMPERED   => self::ARTIFACT_TAMPERED,
            default                      => throw new \InvalidArgumentException(sprintf('The %s finding is not a finding of an artifact.', $finding->value)),
        };
    }
}
