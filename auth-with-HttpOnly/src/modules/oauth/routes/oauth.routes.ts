import type { FastifyInstance } from "fastify";
import { googleCallbackHandler } from "../controllers/oauth.controller.js";

export async function oauthRoutes(app:FastifyInstance){

    app.get('/google/callback',googleCallbackHandler)

}