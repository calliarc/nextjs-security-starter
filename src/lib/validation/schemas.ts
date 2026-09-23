import { z } from "zod";

export const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(254));

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required").max(256),
});

export const messageSchema = z
  .object({
    message: z.string().trim().min(1, "Message is required").max(500, "Message is too long"),
  })
  .strict();

export const noteSchema = z.object({
  note: z.string().trim().min(1, "Note is required").max(280, "Note is too long"),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type MessageInput = z.infer<typeof messageSchema>;
