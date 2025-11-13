import CreditRequest from "./creditRequest.model.js"

const applyCreditRequestIntoDB = async(payload) =>{
    const email = payload?.email;
    const existingLoan = await CreditRequest.findOne({email});
    if(existingLoan){
        throw new Error(`You are already applying for loan. Your loan has been ${existingLoan?.status}`);
    }
    const result = await CreditRequest.create(payload);
    return result;
}
const getCreditRequestFromDB = async() =>{
    const result = await CreditRequest.find();
    return result;
}

export const CreditRequestServices = {
    applyCreditRequestIntoDB,
    getCreditRequestFromDB
}