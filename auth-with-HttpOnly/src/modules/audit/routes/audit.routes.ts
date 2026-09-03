import type { FastifyInstance } from "fastify";

import { getAuditLogsController } from "../controllers/audit.controller.js";

export async function auditRoutes(fastify: FastifyInstance) {
    fastify.get(
        "/",
        getAuditLogsController
    );
}