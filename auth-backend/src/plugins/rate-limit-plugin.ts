import fp from "fastify-plugin";
import rateLimit from "@fastify/rate-limit";
import type { FastifyPluginAsync } from "fastify";
import { env } from "../config/env.js";
export const  rateLimitPlugin:FastifyPluginAsync = fp(async(fastify)=>{
await fastify.register(rateLimit,{
    max:env.RATE_LIMIT_MAX,
    timeWindow:env.RATE_LIMIT_WINDOW,
})
})