// POST /2fa/setup
// POST /2fa/verify
// POST /2fa/complete-login

import type { FastifyPluginAsync } from "fastify";
import { authGuard } from "../../../middleware/authGuard.js";
import { twoFactorController } from "../controller/two-factor.controller.js";
import { completeTwoFactorLoginSchema, verifyTwoFactorSchema } from "../schemas/two-factor.schema.js";


const twoFactorRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.post(
    "/setup",
    {
      preHandler: authGuard,
    },
    twoFactorController.setup
  );

  fastify.post(
    "/verify",
    {
      preHandler: authGuard,
      schema: {
        body: verifyTwoFactorSchema,
      },
    },
    twoFactorController.verify
  );

  // Completes 2FA login: accepts challengeToken (from POST /api/auth/login) + TOTP code
  // No authGuard — the user does not have a real session yet
  fastify.post(
    "/complete-login",
    {
      schema: {
        body: completeTwoFactorLoginSchema,
      },
    },
    twoFactorController.completeLogin
  );
};

export default twoFactorRoutes;
