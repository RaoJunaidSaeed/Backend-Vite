const User = require('../models/User');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('../utils/handlerFactory');
// const multer = require('multer');
const { cloudinary } = require('../utils/cloudinary');
const path = require('path');
const fs = require('fs');

exports.getAllUsers = factory.getAll(User);
exports.getUser = factory.getOne(User);
// exports.updateUser = factory.updateOne(User);
exports.deleteUser = factory.deleteOne(User);

exports.createUser = catchAsync(async (req, res, next) => {
  // For creating a user by an admin, ensure password and passwordConfirm are provided
  if (!req.body.password || !req.body.passwordConfirm) {
    return next(new AppError('Please provide password and passwordConfirm for new user!', 400));
  }
  const newUser = await User.create(req.body);

  res.status(201).json({
    status: 'success',
    data: {
      user: newUser,
    },
  });
});

exports.getMe = (req, res, next) => {
  req.params.id = req.user.id; // sets req.params.id so `getUser` works
  next();
};

exports.deleteMe = catchAsync(async (req, res, next) => {
  // Instead of deleting the user from the database, we just mark them as inactive (soft delete)
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

exports.updateMe = async (req, res, next) => {
  try {
    const updates = {
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      phoneNumber: req.body.phoneNumber,
    };

    if (req.file) {
      updates.photo = req.file.path; // or secure_url
    }

    const updatedUser = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      status: 'success',
      user: updatedUser,
    });
  } catch (err) {
    res.status(400).json({
      status: 'Fail',
      message: `Invalid photo: ${req.file}`, // or handle error better
    });
  }
};

exports.updateUser = catchAsync(async (req, res, next) => {
  console.log(req.body);
  const updates = {};

  // Conditionally assign fields if present
  if (req.body.firstName !== undefined) updates.firstName = req.body.firstName;
  if (req.body.lastName !== undefined) updates.lastName = req.body.lastName;
  if (req.body.email !== undefined) updates.email = req.body.email;
  if (req.body.phoneNumber !== undefined) updates.phoneNumber = req.body.phoneNumber;
  if (req.body.role !== undefined) updates.role = req.body.role;
  if (req.body.active !== undefined) {
    // convert string to boolean if needed
    updates.active =
      typeof req.body.active === 'boolean' ? req.body.active : req.body.active === 'true';
  }

  // If file was uploaded
  if (req.file) {
    updates.photo = req.file.path; // or req.file.secure_url
  }

  const updatedUser = await User.findByIdAndUpdate(req.params.id, updates, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser,
    },
  });
});

// exports.updateUser = catchAsync(async (req, res, next) => {
//   const updates = {
//     firstName: req.body.firstName,
//     lastName: req.body.lastName,
//     email: req.body.email,
//     phoneNumber: req.body.phoneNumber,
//     role: req.body.role,
//     active: req.body.active,
//   };

//   // If photo file is uploaded
//   if (req.file) {
//     updates.photo = req.file.path; // If using Cloudinary, use req.file.secure_url
//   }

//   const updatedUser = await User.findByIdAndUpdate(req.params.id, updates, {
//     new: true,
//     runValidators: true,
//   });

//   res.status(200).json({
//     status: 'success',
//     data: {
//       user: updatedUser,
//     },
//   });
// });
