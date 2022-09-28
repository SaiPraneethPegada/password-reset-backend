const mongoose = require("mongoose");
const validator = require("validator");

var userSchema = new mongoose.Schema(
  {
    userName: { type: String, minLength: 6, unique: true, required: [true, "please enter a name"] },
    email: {
      type: String,
      required: [true, "Please enter an email address"],
      lowercase: true,
      unique: true,
      validate: (value) => {
        return validator.isEmail(value);
      },
    },
    password: { type: String, min: 8 ,required: [true, "please enter your password"] },
  },
  { timestamps: true }
);

const userDetails = mongoose.model("users", userSchema);

module.exports = { userDetails };
