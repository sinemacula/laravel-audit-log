<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

/**
 * A revision of a watched invoice: a subclass kept in the same table, which is
 * never watched through its parent, so it is watched on its own when it is
 * watched at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WatchedInvoiceRevision extends WatchedInvoice {}
