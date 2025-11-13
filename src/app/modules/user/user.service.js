import User from "./user.model.js";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
// import config from "../../config/index.js";


const createUserIntoDB = async(payload) =>{
    const exitingUser = await User.findOne({email: payload?.email});
    if(exitingUser){
        throw new Error("User already exists");
    }
    const result = await User.create(payload);
    return result;
}
const loginUserFromDB = async(payload) =>{
    const {email, password} = payload;
    const exitingUser = await User.findOne({email: email});
    if(!exitingUser){
        throw new Error("User does not exists");
    }
    const isPasswordMatched = await bcrypt.compare(password, exitingUser.password);
    if(!isPasswordMatched){
        throw new Error("Password is incorrect");
    }
    return exitingUser;
}
const updatePasswordInDB = async(payload) =>{
    const {email, currentPassword, newPassword} = payload;
    const existingUser = await User.findOne({email});
    if(!existingUser){
        throw new Error("User does not exists");
    }
    const comparePassword = await bcrypt.compare(currentPassword, existingUser.password);
    if(!comparePassword){
        throw new Error("Password is incorrect. Please enter the correct password");
    }
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    const result = await User.findOneAndUpdate({email}, {password: newPasswordHash}, {new: true});
    return result;
}
const sendOtpFromNodemailer = async(email) =>{
    const existingUser = await User.findOne({email});
    if(!existingUser){
        throw new Error("User not found. Please enter the valid email");
    }
    const otp = Math.floor(Math.random() * 900000); // 6 digit otp
    const expires = Date.now() + 5 * 60 * 1000; //5 minite
    existingUser.forgotPasswordOtp = otp;
    existingUser.forgotPasswordExpires = expires;
    await existingUser.save();

    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        auth: {
            user: process.env.EMAIL, //config.email,
            pass: process.env.PASS //config.pass
        }
    })
    await transporter.sendMail({
        from: config.email,
        to: email,
        subject: "Password Reset OTP",
        text: `Your OTP code is ${otp}. It will expire in 5 minutes.`
    })
    return;
}
const verifyOtpFromDB = async(email, otp) =>{
    const existingUser = await User.findOne({email});
    if(!existingUser){
        throw new Error("User not found");
    }
    if(existingUser.forgotPasswordOtp !== otp){
        throw new Error("Invalid otp. Please enter a valid otp code");
    }
    if(existingUser.forgotPasswordExpires < Date.now()){
        throw new Error("OTP expired. Please OTP send again");
    }
    return;
}
const resetPasswordFromDB = async(email, password) =>{
    const existingUser = await User.findOne({email});
    if(!existingUser){
        throw new Error("User not fount");
    }
    const hashPassword = await bcrypt.hash(password, 10);
    const result = await User.findOneAndUpdate({email}, {password: hashPassword});
    return result;
}

export const UserServices = {
    createUserIntoDB,
    loginUserFromDB,
    // updatePersonalInformationInDB,
    updatePasswordInDB,
    sendOtpFromNodemailer,
    verifyOtpFromDB,
    resetPasswordFromDB
}