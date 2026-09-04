import { z } from "zod";

export const verifyTwoFactorSchema = z.object({
  code: z
    .string()
    .regex(/^\d{6}$/, "Authentication code must be 6 digits"),
});

export type VerifyTwoFactorInput = z.infer<typeof verifyTwoFactorSchema>;