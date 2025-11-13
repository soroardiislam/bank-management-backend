import CreditRequest from "../creditRequest/creditRequest.model.js";
import CreditDecision from "./creditDecision.model.js"

const createCreditDecisionIntoBD = async(payload) =>{
    const email = payload?.email;
    const existingLoan = await CreditDecision.findOne({email});
    // console.log(existingLoan);
    if(existingLoan){
        throw new Error(`You already ${existingLoan?.status} this loan`);
    }
    else{
        await CreditRequest.findOneAndUpdate({email}, {status: payload?.status})
        const result = await CreditDecision.create(payload);
        return result;
    }
}
const getLoanStatusFromBD = async(email) =>{
    const result = await CreditDecision.findOne({email});
    return result;
}

export const CreditDecisionServices = {
    createCreditDecisionIntoBD,
    getLoanStatusFromBD
}