import catchAsync from "../../utils/catchAsync.js";
import sendResponse from "../../utils/sendResponse.js";
import { ProfileServices } from "./profile.service.js";
import statusCodes from "http-status";

const updateProfile = catchAsync(async(req, res) =>{
    const {userId} = req.params;
    const {clientInfo} = req.body;
    // console.log(profileInfo);
    const result = await ProfileServices.updateProfileInDB(userId, clientInfo);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Profile Updated Successfully",
        data: result
    })
})
const getProfile = catchAsync(async(req, res) =>{
    const {userId} = req.params;
    const result = await ProfileServices.getProfileFromDB(userId);
    sendResponse(res, {
        statusCode: statusCodes.OK,
        success: true,
        message: "Profile data retrieved Successfully",
        data: result
    })
})
export const ProfileControllers = {
    updateProfile,
    getProfile
}