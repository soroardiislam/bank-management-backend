import catchAsync from "../../utils/catchAsync.js";
import sendResponse from "../../utils/sendResponse.js";
import { UserServices } from "./user.service.js";
import statusCodes from "http-status";


const createUser = catchAsync(async(req, res) =>{
    const {clientInfo} = req.body;
    // console.log("newUser", newUser);
    const result = await UserServices.createUserIntoDB(clientInfo);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "User sign up successfully",
        data: result
    })
})
const loginUser = catchAsync(async(req, res) =>{
    const {clientInfo} = req.body;
    const result = await UserServices.loginUserFromDB(clientInfo);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "User login successfully",
        data: result
    })
})
const updatePassword = catchAsync(async(req, res) =>{
    const newUpdatePasswordInfo = req.body;
    const result = await UserServices.updatePasswordInDB(newUpdatePasswordInfo);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Password updated successfully",
        data: result
    })
})
const sendOtp = catchAsync(async(req, res) =>{
    const {email} = req.body;
    const result = await UserServices.sendOtpFromNodemailer(email);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Otp send Successfully",
        data: result
    })
})
const verifyOtp = catchAsync(async(req, res) =>{
    const {otp, email} = req.body;
    const result = await UserServices.verifyOtpFromDB(email, otp);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "OTP verified. You can reset your password now",
        data: result
    })
})

const resetPassword = catchAsync(async(req, res) =>{
    const {email, password} = req.body;
    // console.log("email", email, password);
    const result = await UserServices.resetPasswordFromDB(email, password);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Password Reset Successfully",
        data: result
    })
})

export const UserControllers = {
    createUser,
    loginUser,
    updatePassword,
    sendOtp,
    verifyOtp,
    resetPassword
}