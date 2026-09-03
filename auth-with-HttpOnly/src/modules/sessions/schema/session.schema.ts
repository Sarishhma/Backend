import { z } from "zod";


export const sessionParamsSchema = z.object({
  sessionId:z.string().uuid("invalid session Id")
})
export type sessionParamsInput = z.infer<typeof sessionParamsSchema>