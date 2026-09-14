// src/modules/.../schemas/common.schema.ts
import { z } from "zod";

export const errorResponseSchema = z.object({
  success: z.literal(false),
  message: z.string(),
  statusCode: z.number().int(),
});

export const messageResponseSchema = z.object({
  success: z.literal(true),
  message: z.string(),
});

export const userSchema = z.object({
  sub: z.string(),
    email: z.string().email(),
  
});