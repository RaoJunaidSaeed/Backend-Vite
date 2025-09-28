const User = require("../models/User");
const AppError = require("../utils/appError");

exports.getUserById = async (id) => {
  const user = await User.findById(id);
  if (!user) {
    throw new AppError("No user found with that ID", 404);
  }
  return user;
};

exports.updateUser = async (id, data) => {
  const user = await User.findByIdAndUpdate(id, data, {
    new: true,
    runValidators: true,
  });
  if (!user) {
    throw new AppError("No user found with that ID", 404);
  }
  return user;
};

exports.deleteUser = async (id) => {
  const user = await User.findByIdAndDelete(id);
  if (!user) {
    throw new AppError("No user found with that ID", 404);
  }
  return null;
};

exports.getAllUsers = async () => {
  const users = await User.find();
  return users;
};


