import catchAsync from "../../utils/catchAsync.js";
import sendResponse from "../../utils/sendResponse.js";
import { CreditRequestServices } from "./creditRequest.service.js";
import statusCodes from "http-status";

const applyCreditRequest = catchAsync(async(req, res) =>{
    const {clientInfo} = req.body;
    const result = await CreditRequestServices.applyCreditRequestIntoDB(clientInfo);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Your apply is complete",
        data: result
    })
})
const getCreditRequest = catchAsync(async(req, res) =>{
    const result = await CreditRequestServices.getCreditRequestFromDB();
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Recieved all credit request",
        data: result
    })
})

export const CreditRequestControllers = {
    applyCreditRequest,
    getCreditRequest
}