// This is the thin layer that connects Fastify's request/reply objects to the service functions we just built.
//  After everything we've done, this file will feel refreshingly simple — because all the hard logic already lives in 
// auth.service.ts.
import type {FastifyRequest,FastifyReply} from "fastify";
import type { ForgotPasswordInput, LoginInput, LogoutInput, RefreshTokenInput, RegisterInput, ResendOtpInput, ResetPasswordInput, VerifyEmailInput } from "./auth.schema.js";
import { forgotPassword, loginUser, logoutUser, refreshAccessToken, registerUser, resendOtp, resetPassword, verifyEmail } from "./auth.service.js";

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
     reply.setCookie("accessToken",result.accessToken,{
        httpOnly:true,//the core protection we discussed: makes this cookie completely invisible to JavaScript (document.cookie won't show it). Only the browser itself can read/send it.
        secure:process.env.NODE_ENV === "production",//n production, this cookie will ONLY be sent over HTTPS. We disable this requirement locally (development) because your local server runs on plain http://localhost — if we forced secure: true right now, your browser/Postman would silently refuse to store the cookie at all, since there's no HTTPS connection to attach it to.
        sameSite:"strict",//your CSRF defense
        path:'/',//means this cookie gets attached to EVERY request to your domain, at any path. Makes sense — you'll need the access token available on many different protected routes.
        maxAge:15*60//age in second,
    });
     reply.setCookie("refreshToken",result.refreshToken,{
        httpOnly:true,
        secure:process.env.NODE_ENV==="production",
        sameSite:"strict",
        path:'/',
        maxAge:7*24*60*60,
    });
    return reply.status(200).send({user:result.user})
}

export async function refreshHandler(
    request:FastifyRequest,
    reply:FastifyReply
){
const refreshToken= request.cookies.refreshToken;
if(!refreshToken){
    return reply.status(401).send({error:"No refresh token provided"})
}
const result = await refreshAccessToken(refreshToken)
reply.setCookie("accessToken",result.accessToken,{
    httpOnly:true,
    secure:process.env.NODE_ENV==="production",
    sameSite:"strict",
    path:"/",
    maxAge:15*60
})
reply.setCookie("refreshToken",result.refreshToken,{
    httpOnly:true,
    secure:process.env.NODE_ENV==="production",
    sameSite:"strict",
    path:"/",
    maxAge:7*24*60*60

})
return reply.status(200).send({message:"Token refreshed"})
}

export async function logoutHandler(
    request :FastifyRequest,
    reply:FastifyReply
){
  const refreshToken=request.cookies.refreshToken;  
    if(refreshToken){
        await logoutUser(refreshToken)
    }
   
   reply.clearCookie("accessToken",{path:'/'});
   reply.clearCookie("refreshToken",{path:"/api/auth/refresh"});
     return reply.status(200).send({ message: "Logged out" });
}

export async function resendOtpHandler(
    request:FastifyRequest<{Body:ResendOtpInput}>,
    reply:FastifyReply
){
    const {email}=request.body;
    const result =await resendOtp(email);
    return reply.status(200).send(result)

}

export async function forgotPasswordhandler(
    request: FastifyRequest<{Body:ForgotPasswordInput}>,
    reply:FastifyReply
) {
    const {email}=request.body;
    const result= await forgotPassword(email);
    return reply.status(200).send(result)
}

export async function resetPasswordHandler(
    request:FastifyRequest<{Body:ResetPasswordInput}>,
    reply:FastifyReply
) {
    const {email,otp,newPassword}=request.body;
    const result = await resetPassword(email,otp,newPassword);
    return reply.status(200).send(result)
}