import { z } from "zod";
import { AuditEventType } from "../../../generated/prisma/enums.js";

export const auditLogQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),

    eventType: z.nativeEnum(AuditEventType).optional(),

    userId: z.string().optional(),
});