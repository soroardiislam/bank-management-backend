import mongoose, {model, Schema} from "mongoose";

const profileSchema = new Schema({
    personalInfo: {
        type: {
            firstName: {
                type: String
            },
            lastName: {
                type: String
            },
            dateOfBirth: {
                type: String
            },
            gender: {
                type: String
            }
        },
        _id: false
    },
    contactInfo: {
        type: {
            address: {
                type: String
            },
            city: {
                type: String
            },
            state: {
                type: String
            },
            zipCode: {
                type: String
            }
        },
        _id: false
    },
    financialInfo: {
        type: {
            annualIncome: {
                type: Number
            },
            valueOfLandOwnership: {
                type: Number
            },
            electricityBill: {
                type: Number
            },
            mobileMoneyBalance: {
                type: Number
            },
            existingLoan: {
                type: String
            },
            existingLoanAmount: {
                type: Number
            },
            terms: {
                type: String
            },
        },
        _id: false
    },
    profileId: {
        type: String
    },
    user: {
        type: Schema.Types.ObjectId,
        ref: "User"
    }
})

const Profile = mongoose.models.Profile || model("Profile", profileSchema);
export default Profile;