// POST /2fa/setup
// POST /2fa/verify
// POST /2fa/disable

import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { authGuard } from "../../../middleware/authGuard.js";
import { twoFactorController } from "../controller/two-factor.controller.js";
import { verifyTwoFactorSchema } from "../schemas/two-factor.schema.js";


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
};

export default twoFactorRoutes;