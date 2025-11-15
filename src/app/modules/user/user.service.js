import User from "./user.model.js";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";

// Create new user
const createUserIntoDB = async (payload) => {
  const existingUser = await User.findOne({ email: payload?.email });
  if (existingUser) {
    throw new Error("User already exists");
  }
  const result = await User.create(payload);
  return result;
};

// Login user
const loginUserFromDB = async (payload) => {
  const { email, password } = payload;
  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    throw new Error("User does not exist");
  }

  const isPasswordMatched = await bcrypt.compare(password, existingUser.password);
  if (!isPasswordMatched) {
    throw new Error("Password is incorrect");
  }

  return existingUser;
};

// Update password
const updatePasswordInDB = async (payload) => {
  const { email, currentPassword, newPassword } = payload;
  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    throw new Error("User does not exist");
  }

  const comparePassword = await bcrypt.compare(currentPassword, existingUser.password);
  if (!comparePassword) {
    throw new Error("Current password is incorrect");
  }

  const newPasswordHash = await bcrypt.hash(newPassword, 10);
  const result = await User.findOneAndUpdate(
    { email },
    { password: newPasswordHash },
    { new: true }
  );
  return result;
};

// Send OTP via email
const sendOtpFromNodemailer = async (email) => {
  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    throw new Error("User not found. Please enter a valid email");
  }

  const otp = Math.floor(100000 + Math.random() * 900000); 
  const expires = Date.now() + 5 * 60 * 1000; 

  existingUser.forgotPasswordOtp = otp;
  existingUser.forgotPasswordExpires = expires;
  await existingUser.save();

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL, 
      pass: process.env.PASS   
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL,   
    to: email,
    subject: "Password Reset OTP",
    text: `Your OTP code is ${otp}. It will expire in 5 minutes.`
  });

  return;
};

// Verify OTP
const verifyOtpFromDB = async (email, otp) => {
  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    throw new Error("User not found");
  }
  if (existingUser.forgotPasswordOtp !== otp) {
    throw new Error("Invalid OTP. Please enter a valid OTP code");
  }
  if (existingUser.forgotPasswordExpires < Date.now()) {
    throw new Error("OTP expired. Please request OTP again");
  }
  return;
};

// Reset password
const resetPasswordFromDB = async (email, password) => {
  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    throw new Error("User not found");
  }

  const hashPassword = await bcrypt.hash(password, 10);
  const result = await User.findOneAndUpdate(
    { email },
    { password: hashPassword },
    { new: true }
  );

  return result;
};

export const UserServices = {
  createUserIntoDB,
  loginUserFromDB,
  updatePasswordInDB,
  sendOtpFromNodemailer,
  verifyOtpFromDB,
  resetPasswordFromDB
};
