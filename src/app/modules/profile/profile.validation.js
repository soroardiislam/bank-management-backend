import z from "zod";

const profileValidationSchema = z.object({
    personalInfo: z.object({
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    dateOfBirth: z.string().optional(),
    gender: z.string().optional(),
  }),

  contactInfo: z.object({
    address: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    zipCode: z.string().optional(),
  }),

  financialInfo: z.object({
    annualIncome: z.number().optional(),
    valueOfLandOwnership: z.number().optional(),
    electricityBill: z.number().optional(),
    mobileMoneyBalance: z.number().optional(),
    existingLoan: z.string().optional(),
    existingLoanAmount: z.number().optional(),
    terms: z.string().optional(),
  }),

  profileId: z.string().optional(),

  user: z.string().optional(),
})

export default profileValidationSchema;