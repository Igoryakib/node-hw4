const { Schema, model } = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new Schema(
  {
    password: {
      type: String,
      required: [true, "Set password for user"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
    },
    subscription: {
      type: String,
      enum: ["starter", "pro", "business"],
      default: "starter",
    },
    token: String,
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

userSchema.methods.validatePassword = function (rawPassword) {
  const hashedPassword = this.password;
  return bcrypt.compare(rawPassword, hashedPassword);
};

userSchema.statics.hashPassword = function (rawPassword) {
  return bcrypt.hash(rawPassword, 12);
};

module.exports = model("user", userSchema);
