import z from "zod";

const createUserValidationSchema = z.object({
    email: z.email("Email is required"),
    phone: z.number().optional(),
    password: z.string("password is required"),
    terms: z.string("Terms is required"),
    role: z.enum(["user", "admin"]).default("user")
})

const userSignInValidationSchema = z.object({
    email: z.email("Email is required"),
    password: z.string("password is required"),
    terms: z.string("Terms is required")
})

export const userValidationSchema = {
    createUserValidationSchema,
    userSignInValidationSchema
};