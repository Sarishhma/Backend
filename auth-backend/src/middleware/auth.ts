import type { FastifyRequest, FastifyReply } from "fastify";
import { verifyAccessToken } from "../utils/token.js";
import { unauthorized } from "../utils/app-error.js";

export async function authGuard(request: FastifyRequest, reply: FastifyReply) {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw unauthorized("Missing or invalid authorization header");
  }

  const token = authHeader.slice("Bearer ".length);

  try {
    const decoded = verifyAccessToken(token);
    request.user = decoded;
  } catch {
    throw unauthorized("Invalid or expired access token");
  }
}