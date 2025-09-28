const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const AppError = require("../utils/appError");

exports.signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

exports.verifyToken = async (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return reject(new AppError("Invalid token", 401));
      resolve(decoded);
    });
  });
};

exports.signup = async (userData) => {
  const newUser = await User.create({
    firstName: userData.firstName,
    lastName: userData.lastName,
    email: userData.email,
    password: userData.password,
    role: userData.role || "tenant", // Default role
    phoneNumber: userData.phoneNumber,
  });
  // In a real app, you'd generate and send OTP here
  return newUser;
};

exports.login = async (email, password) => {
  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return null; // Or throw a specific error for controller to handle
  }
  return user;
};

// Add other service methods as needed (e.g., for OTP generation/sending)


