import z from "zod";

const creditRequestValidationSchema = z.object({
    status: z.string({
        required_error: "Status is required",
    }),
    email: z.email({
        required_error: "Email is required"
    }),
    creditInfo: z.object({
    clientName: z.string({
      required_error: "Client name is required",
    }),
    dateOfBirth: z.string({
      required_error: "Date of Birth is required",
    }),
    gender: z.string({
      required_error: "Gender is required",
    }),
    lacation: z.string({
      required_error: "Location is required",
    }),
    phone: z.string({
      required_error: "Mobile Number is required",
    }),
  }),
  financialInfo: z.object({
    annualIncome: z.number({
      required_error: "Annual Income is required",
    }),
    creditScore: z.number({
      required_error: "Credit Score is required",
    }),
    creditTag: z.string({
      required_error: "Credit tag is required",
    }),
    existingLoan: z.enum(["yes", "no"]),
    loanAmount: z.number({
      required_error: "Loan Amount is required",
    }),
    mobileMoneyBalance: z.number({
      required_error: "Mobile Money Balance is required",
    }),
    valueOfLandOwnership: z.number({
      required_error: "Value of Land Ownership is required",
    }),
    electricityBill: z.number({
      required_error: "electricityBill is required",
    }),
    existingLoanAmount: z.any({
      required_error: "existingLoanAmount is required",
    }).optional()
  })
})

export default creditRequestValidationSchema;