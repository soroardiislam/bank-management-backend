import z from "zod";

const creditRequestValidationSchema = z.object({
    email: z.email({
        required_error: "Email is required",
    }),
    interestRate: z.number().optional(),
    loanAmount: z.number().optional(),
    notes: z.string({
        required_error: "Notes are required"
    }),
    status: z.enum(["approve", "reject"]),
    terms: z.enum(["3", "6", "12", "24", "36"]).optional()
})

export default creditRequestValidationSchema;