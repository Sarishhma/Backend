import oauthPlugin from "@fastify/oauth2";
import type { FastifyInstance } from "fastify";
import { env } from "./env.js";

export async function registerGoogleOAuth(app: FastifyInstance) {
  await app.register(oauthPlugin, {
    name: "googleOAuth2",

    scope: ["openid", "email", "profile"],

    credentials: {
      client: {
        id: env.GOOGLE_CLIENT_ID,
        secret: env.GOOGLE_CLIENT_SECRET,
      },
      auth: {
        authorizeHost: "https://accounts.google.com",
        authorizePath: "/o/oauth2/v2/auth",
        tokenHost: "https://oauth2.googleapis.com",
        tokenPath: "/token",
      },
    },

    startRedirectPath: "/api/auth/google",
    callbackUri: env.GOOGLE_CALLBACK_URL,
  });
}