import mongoose, {model, Schema} from "mongoose";

const creditRequestSchema = new Schema({
    status: {
        type: String,
        required: true
    },
    email: {type: String, required: [true, "Email is required"], unique: true},
    creditInfo: {
        type: {
            clientName: {type: String, required: true},
            dateOfBirth: {type: String, required: true},
            gender: {type: String, required: true},
            lacation: {type: String, required: true},
            phone: {type: String, required: [true, "Mobile Number is required"]}
        },
        _id: false
    },
    financialInfo: {
        type: {
            annualIncome: {type: Number, required: true},
            creditScore: {type: Number, required: true},
            existingLoan: {type: String, required: true},
            loanAmount: {type: Number, required: true},
            mobileMoneyBalance: {type: Number, required: true},
            valueOfLandOwnership: {type: Number, required: true},
            creditTag: {type: String, required: true},
            electricityBill: {type: String, required: true},
            existingLoanAmount: {type: Number}
        },
        _id: false
    }
})

const CreditRequest = mongoose.models.CreditRequest || model("CreditRequest", creditRequestSchema);

export default CreditRequest;