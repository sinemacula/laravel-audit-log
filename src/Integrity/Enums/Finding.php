<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * The check a verification or a seal run found failing, each with the integrity
 * status it gives. Within one status the cases are in order of precedence, so
 * when a segment fails several checks of its most severe status, the first of
 * them in this order is the one reported.
 *
 * A finding names the check and never a value of an entry, so it can be shown,
 * logged and alerted on as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Finding: string
{
    // A seal row is not a well-formed seal, or its signature is malformed
    case SEAL_MALFORMED = 'seal_malformed';

    // A seal is of an algorithm version or a signer this release does not read
    case SEAL_VERSION = 'seal_version';

    // A seal is signed under a key the ring does not hold
    case SEAL_KEY = 'seal_key';

    // A seal names another log than the one configured
    case LOG_MISMATCH = 'log_mismatch';

    // A seal's stored digest is not the digest of its fields
    case SEAL_DIGEST = 'seal_digest';

    // A seal's signature does not match its digest
    case SEAL_SIGNATURE = 'seal_signature';

    // The first seal links to a previous one, or a later seal links to none
    case GENESIS = 'genesis';

    // A seal's sequence is not the one that follows the seal before it, a seal
    // the range needs is missing, or a seal is stored outside the chain
    case SEQUENCE_GAP = 'sequence_gap';

    // A seal does not link to the id and digest of the seal before it
    case CHAIN_BROKEN = 'chain_broken';

    // A seal's member rows are not as many as the seal counts
    case MEMBER_COUNT = 'member_count';

    // A seal's member rows are not the members it sealed
    case MEMBERS_DIGEST = 'members_digest';

    // The anchor holds another digest for a seal, or a seal it holds is missing
    // locally
    case ANCHOR_CONTRADICTION = 'anchor_contradiction';

    // The anchor refused a seal because it already holds another digest for the
    // seal's sequence
    case ANCHOR_CONFLICT = 'anchor_conflict';

    // The anchor holds seals past the local log's head
    case MISSING_TAIL = 'missing_tail';

    // A member row belongs to no seal
    case ORPHAN_MEMBER = 'orphan_member';

    // A prune record is forged, or does not match the seal it names
    case PRUNE_RECORD = 'prune_record';

    // An entry's stored signature is not the one its seal recorded
    case MEMBER_HMAC = 'member_hmac';

    // An entry's signature does not match its content
    case ENTRY_HMAC = 'entry_hmac';

    // An entry's manifest names an artifact that is not stored
    case MANIFEST_MISSING = 'manifest_missing';

    // An entry's artifact counts other members, or holds another digest, than
    // its manifest signed
    case MANIFEST_MISMATCH = 'manifest_mismatch';

    // An entry's artifact is stored under another id than its manifest signed,
    // or names another entry
    case MANIFEST_SWAPPED = 'manifest_swapped';

    // An entry's artifact is stored as another kind than its manifest signed
    case MANIFEST_WRONG_KIND = 'manifest_wrong_kind';

    // An entry's manifest is not a well-formed descriptor, or its artifact's
    // members are no canonical form of the kind the manifest signed
    case MANIFEST_MALFORMED = 'manifest_malformed';

    // An entry's artifact's members are a canonical form of the signed kind,
    // but not the one its manifest signed
    case MANIFEST_TAMPERED = 'manifest_tampered';

    // A journal row's sequence is missing, repeated or out of order, its
    // previous HMAC is not its predecessor's, or it names another log
    case JOURNAL_GAP = 'journal_gap';

    // A journal row's HMAC, or its payload's digest, does not match
    case JOURNAL_SIGNATURE = 'journal_signature';

    // A seal's journal commitment names no row of the chain, runs backwards, or
    // is empty after a seal that committed to a row
    case JOURNAL_COMMITMENT = 'journal_commitment';

    // A journal row is a transition its chain does not allow, such as the
    // release of a hold that is not active or a hold placed twice
    case JOURNAL_TRANSITION = 'journal_transition';

    // A prune record is signed under a key the ring does not hold
    case PRUNE_KEY = 'prune_key';

    // An entry is not a well-formed record, so it cannot be verified or sealed
    case ENTRY_MALFORMED = 'entry_malformed';

    // An entry is signed under a key the ring does not hold
    case ENTRY_KEY = 'entry_key';

    // An entry's artifact cannot be decrypted with the application's keys
    case MANIFEST_UNREADABLE = 'manifest_unreadable';

    // A journal row is signed under a key the ring does not hold
    case JOURNAL_KEY = 'journal_key';

    // A journal row cannot be read as a journal row
    case JOURNAL_MALFORMED = 'journal_malformed';

    // A sealed entry is missing, with no prune record to account for it
    case MISSING_ENTRY = 'missing_entry';

    // Entries older than the allowed age are still unsealed
    case OVERDUE_UNSEALED = 'overdue_unsealed';

    // Unsealed entries are recorded so far ahead of the clock that no seal
    // takes them
    case FUTURE_UNSEALED = 'future_unsealed';

    // A member a valid prune record covers is still, or again, present
    case RESURRECTED = 'resurrected';

    /**
     * The integrity status the finding gives: `tampered` for a check that shows
     * the log was altered, `unverifiable` for one that could not be made, and
     * `incomplete` for entries that are missing, unsealed, or present after
     * their prune.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus
     */
    public function status(): IntegrityStatus
    {
        return match ($this) {
            self::SEAL_MALFORMED,
            self::SEAL_VERSION,
            self::SEAL_KEY,
            self::LOG_MISMATCH,
            self::PRUNE_KEY,
            self::ENTRY_MALFORMED,
            self::ENTRY_KEY,
            self::MANIFEST_UNREADABLE,
            self::JOURNAL_KEY,
            self::JOURNAL_MALFORMED => IntegrityStatus::UNVERIFIABLE,
            self::MISSING_ENTRY,
            self::OVERDUE_UNSEALED,
            self::FUTURE_UNSEALED,
            self::RESURRECTED => IntegrityStatus::INCOMPLETE,
            default           => IntegrityStatus::TAMPERED,
        };
    }
}
