<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * What the verification of an export found failing, each its own step of the
 * chain, in the order the chain checks them: the bundle, the export entry, its
 * signed descriptor, the artifact that holds the manifest, the manifest the
 * bundle carries, then the file, its membership and each of its lines.
 *
 * A finding names the step and never a value of an entry, so it can be shown,
 * logged and alerted on as it is. An export verifies only with none.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ExportFinding: string
{
    // The bundle beside the file is missing, or not exactly a bundle this
    // release writes
    case BUNDLE_MALFORMED = 'bundle_malformed';

    // The export entry the bundle names is not stored, or the viewer may not
    // see it
    case ENTRY_MISSING = 'entry_missing';

    // The export entry is signed under a key the ring does not hold, under an
    // integrity version this release does not read, or is not a well-formed row
    case ENTRY_UNVERIFIABLE = 'entry_unverifiable';

    // The export entry's signature does not match its content
    case ENTRY_TAMPERED = 'entry_tampered';

    // The entry found is not an export's journal, or not the one the bundle
    // holds
    case ENTRY_SWAPPED = 'entry_swapped';

    // The descriptor the entry signed is not the bundle's, or not an export's
    case DESCRIPTOR_MISMATCH = 'descriptor_mismatch';

    // The artifact the descriptor names is not stored
    case ARTIFACT_MISSING = 'artifact_missing';

    // The artifact is stored under another id than its descriptor signed, or
    // names another entry
    case ARTIFACT_SWAPPED = 'artifact_swapped';

    // The artifact is stored as another kind than its descriptor signed
    case ARTIFACT_WRONG_KIND = 'artifact_wrong_kind';

    // The artifact counts other members, or holds another digest, than its
    // descriptor signed
    case ARTIFACT_MISMATCH = 'artifact_mismatch';

    // The artifact's members cannot be decrypted with the application's keys
    case ARTIFACT_UNDECRYPTABLE = 'artifact_undecryptable';

    // The artifact's members are no canonical export manifest
    case ARTIFACT_MALFORMED = 'artifact_malformed';

    // The artifact's members are a canonical export manifest, but not the one
    // its descriptor signed
    case ARTIFACT_TAMPERED = 'artifact_tampered';

    // The manifest the bundle carries is not the one the journal holds
    case MANIFEST_MISMATCH = 'manifest_mismatch';

    // The file's digest is not the one its manifest holds
    case FILE_MISMATCH = 'file_mismatch';

    // The file's lines, their ids, or its first and last positions are not the
    // ones its manifest holds
    case MEMBERSHIP_MISMATCH = 'membership_mismatch';

    // A line of the file is not a line of its format, or names no id
    case LINE_MALFORMED = 'line_malformed';

    // A line of an NDJSON export is signed under a key the ring does not hold,
    // under an integrity version this release does not read, or lacks a column
    // its signature covers
    case LINE_UNVERIFIABLE = 'line_unverifiable';

    // A line's signature does not match its content
    case LINE_TAMPERED = 'line_tampered';

    /**
     * The finding of an export's artifact for the finding the artifact
     * inspector or a failed decryption gives it, each its own: a missing,
     * swapped, wrong-kind, mismatched, malformed or tampered manifest, and one
     * that could not be read as undecryptable. Any other finding is refused.
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
