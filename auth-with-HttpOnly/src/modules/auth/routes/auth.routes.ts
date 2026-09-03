import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { forgotPasswordSchema, loginSchema, logoutSchema, refreshTokenSchema, registerSchema, resendOtpSchema, resetPasswordSchema, verifyEmailSchema } from "../schemas/auth.schema.js";
import { forgotPasswordhandler, loginHandler, logoutHandler, refreshHandler, registerhandler, resendOtpHandler, resetPasswordHandler, verifyEmailHandler } from "../controllers/auth.controller.js";
import { authGuard } from "../../../middleware/authGuard.js";
import { requireRole } from "../../../middleware/require-role.js";



// Fastify is a web framework whose core job is routing incoming HTTP requests to the right handler code and sending 
// back responses — and it happens to do this job quickly compared to alternatives, plus it has strong built-in support 
// for validating request/response data against schemas (like our Zod schemas).



export const authRoutes:FastifyPluginAsync=async(fastify)=>{
    const app = fastify.withTypeProvider<ZodTypeProvider>();

    app.get("/me", { preHandler: authGuard }, async (request, reply) => {
  return reply.status(200).send({ user: request.user });
});

//preHandler: authGuard actually means: Fastify runs this function BEFORE the actual route handler executes —
//  if authGuard throws (no token, invalid token), the route handler (async (request, reply) => {...}) never even runs; 
// the error goes straight to your error-handler plugin instead. If authGuard
//  succeeds, execution continues into the handler, and by that point, request.user is already populated and ready to use.
app.get("/admin-only",
    {preHandler:[authGuard,requireRole("ADMIN")]},
    async(request,reply)=>{
        return reply.status(200).send({message:"Welcome admin!",user:request.user})
    }
)
    app.post(
        '/register',
        {schema:{body:registerSchema}},
        registerhandler
    );

        app.post(
        '/resend-otp',
        {schema:{body:resendOtpSchema}},
        resendOtpHandler
    )
    
    app.post(
        '/verify-email',
        {schema:{body:verifyEmailSchema}},
        verifyEmailHandler
    )

    app.post(
        '/login',
        {schema:{body:loginSchema}},
        loginHandler
    )

    app.post(
        '/refresh',
        refreshHandler
    )

    app.post (
        '/log-out',
        logoutHandler
    )

    app.post(
        '/forgot-password',
        {schema:{body:forgotPasswordSchema}},
        forgotPasswordhandler
    )

    app.post(
        '/reset-password',
        {schema:{body:resetPasswordSchema}},
        resetPasswordHandler
    )

 


}
