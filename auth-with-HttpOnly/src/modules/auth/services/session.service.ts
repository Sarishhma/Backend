import {
    findActiveSessionsForUser,
    findRefreshTokenByIdAndUser,
    findSessionByIdAndUser,
    revokeRefreshToken,
    revokeSession as revokeSessionRepository,
} from "../repositories/session.repository.js";

import { notFound } from "../../../utils/app-error.js";


export async function getUserSessions(userId: string) {
    const sessions = await findActiveSessionsForUser(userId);

    return sessions.map((session) => ({
        id: session.sessionId,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
        createdAt: session.createdAt,
        lastUsedAt: session.lastUsedAt,
    }));
}


export async function revokeSession(
    sessionId: string,
    userId: string
) {
    const session = await findSessionByIdAndUser(
        sessionId,
        userId
    );

    if (!session) {
        throw notFound("Session not found");
    }

    await revokeSessionRepository(session.id,userId);

    return {
        message: "Session revoked successfully",
    };
}