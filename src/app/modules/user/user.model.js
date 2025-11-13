import mongoose, { model, Schema } from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
    },
    password: {
      type: String,
      required: true
    },
    terms: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },
    forgotPasswordOtp: {
      type: String
    },
    forgotPasswordExpires: {
      type: String
    }
},
  { timestamps: true }
);

userSchema.pre("save", async function(next) {
  this.password = await bcrypt.hash(this.password, 10);
  // console.log(this.password);
  next();
});

const User =  mongoose.models.User || model("User", userSchema);

export default User;
