import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { loginSchema, logoutSchema, refreshTokenSchema, registerSchema } from "./auth.schema.js";
import { loginHandler, logoutHandler, refreshHandler, registerhandler, verifyEmailHandler } from "./auth.controller.js";
import { verifyEmail } from "./auth.service.js";

// Fastify is a web framework whose core job is routing incoming HTTP requests to the right handler code and sending 
// back responses — and it happens to do this job quickly compared to alternatives, plus it has strong built-in support 
// for validating request/response data against schemas (like our Zod schemas).



export const authRoutes:FastifyPluginAsync=async(fastify)=>{
    const app = fastify.withTypeProvider<ZodTypeProvider>();
    app.post(
        '/register',
        {schema:{body:registerSchema}},
        registerhandler
    );
    app.post(
        '/verify-email',
        {schema:{body:verifyEmail}},
        verifyEmailHandler
    )

    app.post(
        '/login',
        {schema:{body:loginSchema}},
        loginHandler
    )

    app.post(
        '/refresh',
        {schema:{body:refreshTokenSchema}},
        refreshHandler
    )

    app.post (
        '/log-out',
        {schema:{body:{logoutSchema}}},
        logoutHandler
    )
}
