<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Querying\Procedure;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The reading guide's subject access policy, `App\Audit\SubjectAccessPolicy`,
 * whose text from its class declaration to its end is the guide's own: the
 * investigator reads, counts and exports the subject's activity, as the actor
 * or the subject of an entry, and verifies the export in the audit category;
 * anyone else sees nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectAccessPolicy implements AuditAccessPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $investigator
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $subject
     */
    public function __construct(

        /** The person answering the request, as the application authenticated them. */
        #[\SensitiveParameter]
        private Authenticatable $investigator,

        /** The person the request is about. */
        private Reference $subject,
    ) {}

    /**
     * The subject's activity, as the actor or the subject of an entry, for the
     * investigator to read, count and export; the audit category, where the
     * export is journalled, for the investigator to verify the export; and
     * nothing for anyone else.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    #[\Override]
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        if ($viewer !== $this->investigator) {
            return AccessScope::none();
        }

        return match ($purpose) {
            ReadPurpose::VERIFY => AccessScope::all()->onlyCategories('audit'),
            default             => AccessScope::all()->onlyAbout($this->subject),
        };
    }
}
