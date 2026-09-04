import type { FastifyReply, FastifyRequest } from "fastify";


import { unauthorized } from "../../../utils/app-error.js";
import { twoFactorService } from "../types/two-factor.service.js";

export const twoFactorController = {
  async setup(request: FastifyRequest, reply: FastifyReply) {
    if (!request.user) {
      throw unauthorized("Unauthorized");
    }

    const result = await twoFactorService.generateSetup(
      request.user.sub,
      request.user.email
    );

    return reply.status(200).send(result);
  },

  async verify(request: FastifyRequest, reply: FastifyReply) {
    if (!request.user) {
      throw unauthorized("Unauthorized");
    }

    const { code } = request.body as { code: string };

    const result = await twoFactorService.verifySetup(
      request.user.sub,
      code
    );

    return reply.status(200).send(result);
  },
};