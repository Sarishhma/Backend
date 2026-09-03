import type { FastifyReply, FastifyRequest } from "fastify";

import {
    getUserSessions,
    revokeSession,
} from "../services/session.service.js";
import type { sessionParamsInput } from "../schema/session.schema.js";


export async function getSessionsHandler(
    request: FastifyRequest,
    reply: FastifyReply
) {
    const sessions = await getUserSessions(request.user!.sub);

    return reply.status(200).send({
        sessions,
    });
}


export async function revokeSessionHandler(
    request: FastifyRequest<{
        Params: sessionParamsInput;
    }>,
    reply: FastifyReply
) {
    const { sessionId } = request.params;

    const result = await revokeSession(
        sessionId,
        request.user!.sub
    );

    return reply.status(200).send(result);
}