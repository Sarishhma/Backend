import type { FastifyInstance } from "fastify";

import {
    getSessionsHandler,
    revokeSessionHandler,
} from "../controllers/session.controller.js";
import { authGuard } from "../../../middleware/authGuard.js";
import type { sessionParamsInput } from "../schemas/session.schema.js";

export async function sessionRoutes(fastify: FastifyInstance) {

    // Get all active sessions for the logged-in user
    fastify.get(
        "/sessions",
        {
            preHandler: authGuard,
        },
        getSessionsHandler
    );

    // Revoke one specific session
    fastify.delete<{Params:sessionParamsInput}>(
        "/sessions/:sessionId",
        {
            preHandler: authGuard,
        },
        revokeSessionHandler
    );
}