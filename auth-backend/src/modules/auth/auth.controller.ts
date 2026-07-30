// This is the thin layer that connects Fastify's request/reply objects to the service functions we just built.
//  After everything we've done, this file will feel refreshingly simple — because all the hard logic already lives in 
// auth.service.ts.
import type {FastifyRequest,FastifyReply} from "fastify";
import type { LoginInput, LogoutInput, RefreshTokenInput, RegisterInput, VerifyEmailInput } from "./auth.schema.js";
import { loginUser, logoutUser, refreshAccessToken, registerUser, verifyEmail } from "./auth.service.js";

// auth.routes.ts  →  auth.controller.ts  →  auth.service.ts
// The controller does NOT take data from the service and hand it to the route. The actual relationship is:

// Fastify (driven by what routes.ts registered) calls the controller function
// The controller calls the service function
// The service returns data (or throws) back up to the controller
// The controller sends that data back out as an HTTP response, via reply.send(...)

//Its core job, plainly: listen on a network port (like 3000), receive incoming HTTP requests, figure out which
//  piece of your code should handle each one based on the URL + method (e.g., POST /api/auth/register → registerHandler),
//  run that code, and send a response back to whoever asked.
export async function registerhandler (
    request: FastifyRequest<{Body:RegisterInput}>,
    reply:FastifyReply

){
const  { email,password}=request.body;
const result = await registerUser(email,password); // ← controller calls service, HERE
return reply.status(201).send(result)
}

export async function verifyEmailHandler(
  request: FastifyRequest<{ Body: VerifyEmailInput }>,
  reply: FastifyReply
) {
  const { email, otp } = request.body;
  const result = await verifyEmail(email, otp);
  return reply.status(200).send(result);
}

export async function loginHandler(
    request: FastifyRequest<{Body:LoginInput}>,
    reply:FastifyReply
){
    const {email, password}=request.body;
    const result = await loginUser(email,password)
    return reply.status(200).send(result) 
}

export async function refreshHandler(
    request:FastifyRequest<{Body:RefreshTokenInput}>,
    reply:FastifyReply
){
const {refreshToken}= request.body;
const result = await refreshAccessToken(refreshToken)
return reply.status(200).send(result)
}

export async function logoutHandler(
    request :FastifyRequest<{Body:LogoutInput}>,
    reply:FastifyReply
){
    const {refreshToken}= request.body;
    const result = await logoutUser(refreshToken)
    return reply.status(200).send(result)
}