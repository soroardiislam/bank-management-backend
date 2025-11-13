import catchAsync from "../utils/catchAsync.js";

const validateRequest = (schema) =>{
    return catchAsync(async(req, res, next) =>{
        await schema.parseAsync(req.body.clientInfo);
        next(); 
    })
}

export default validateRequest;