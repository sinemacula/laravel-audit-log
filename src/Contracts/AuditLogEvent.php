<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Audit log event contract: marks the package's own events, so a listener can
 * tell them apart and the package never maps one to a record.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuditLogEvent {}
