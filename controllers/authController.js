const User = require('../models/User');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const sendEmail = require('../utils/email');
const otpGenerator = require('../utils/otpGenerator');

// Helper function to sign JWT
const signToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const sendToken = (user, statusCode, res) => {
  const token = signToken(user);

  const cookieOptions = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: false, // allow for local HTTP dev
    sameSite: 'Lax', // allows cross-origin cookies from same site over different port
  };

  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true;
    cookieOptions.sameSite = 'None';
  }

  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;
  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

const otpStore = {};

/**
 * 1️⃣ Send OTP (does NOT create user yet)
 */
exports.sendOTP = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new AppError('Please provide your email.', 400));
  }

  const otp = otpGenerator.generateOTP();
  otpStore[email] = {
    otp,
    expires: Date.now() + 10 * 60 * 1000, // 10 minutes
  };

  try {
    await sendEmail(
      email,
      'Rentofix - Email Verification',
      `<p>Your verification OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
    );

    res.status(200).json({
      status: 'success',
      message: 'OTP sent to your email.',
    });
  } catch (err) {
    delete otpStore[email];
    return next(new AppError('Failed to send OTP. Please try again later.', 500));
  }
});

/**
 * 2️⃣ Verify OTP (only validates; does not create user)
 */
exports.verifyOTP = catchAsync(async (req, res, next) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return next(new AppError('Please provide email and OTP.', 400));
  }

  const stored = otpStore[email];

  if (!stored) {
    return next(new AppError('No OTP found for this email. Please request again.', 404));
  }

  if (stored.expires < Date.now()) {
    delete otpStore[email];
    return next(new AppError('OTP expired. Please request a new one.', 400));
  }

  if (stored.otp !== otp) {
    return next(new AppError('Invalid OTP. Please try again.', 400));
  }

  // ✅ OTP verified — mark as verified
  stored.verified = true;

  res.status(200).json({
    status: 'success',
    message: 'OTP verified successfully.',
  });
});

/**
 * 3️⃣ Signup (only allowed if OTP verified)
 */
exports.signup = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  // Ensure OTP verified before allowing signup
  const stored = otpStore[email];

  if (!stored || !stored.verified) {
    return next(new AppError('Please verify your email before signing up.', 400));
  }

  // Create user
  const newUser = await User.create({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    role: req.body.role || 'tenant',
    phoneNumber: req.body.phoneNumber,
    isVerified: true,
  });

  // ✅ Cleanup OTP record after signup
  delete otpStore[email];

  res.status(201).json({
    status: 'success',
    message: 'Signup complete! You can now log in.',
    data: {
      user: newUser,
    },
  });
});

/**
 * 4️⃣ Resend OTP
 */
exports.resendOTP = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new AppError('Please provide your email.', 400));
  }

  const otp = otpGenerator.generateOTP();
  otpStore[email] = {
    otp,
    expires: Date.now() + 10 * 60 * 1000,
  };

  try {
    await sendEmail(
      email,
      'Rentofix - New OTP Code',
      `<p>Your new OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
    );

    res.status(200).json({
      status: 'success',
      message: 'New OTP sent successfully.',
    });
  } catch (err) {
    delete otpStore[email];
    return next(new AppError('Failed to resend OTP.', 500));
  }
});

//////// 2. Login  //////////////
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  // 1) Check if email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  // 2) Check if user exists && password is correct
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // 3) If everything ok, send token to client
  sendToken(user, 200, res);
});

//////// 5. ForgotPassword /////////
// 5. Forgot Password
exports.forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  // 1. Check if email exists
  if (!email) {
    return next(new AppError('Please provide your email address.', 400));
  }

  // 2. Find user by email
  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError('No user found with that email address.', 404));
  }

  // 3. Generate password reset token and save to DB
  const resetToken = await user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  // console.log(process.env.FRONTEND_URL);
  // 4. Create password reset URL
  const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
  // 4. Create password reset URL (pointing to React frontend)
  // const resetURL = `http://localhost:3000/reset-password/${resetToken}`;

  // 5. Construct email content
  const emailHTML = `
    <p>Hello ${user.firstName || 'User'},</p>
    <p>You requested a password reset.</p>
    <p>Click the link below to set a new password:</p>
    <a href="${resetURL}" style="color: blue;">Reset Password</a>
    <p>This link is valid for 10 minutes.</p>
    <p>If you didn’t request this, just ignore this email.</p>
    <br/>
    <p>– Rentofix Team</p>
  `;

  // 6. Try to send email
  try {
    await sendEmail(user.email, 'Rentofix - Password Reset', emailHTML);

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to your email!',
    });
  } catch (err) {
    // Cleanup if email fails
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('Error sending email. Please try again later.', 500));
  }
});

//////// 6. ResetPassword /////////
exports.resetPassword = catchAsync(async (req, res, next) => {
  console.log('hello', req.body);
  const { password, passwordConfirm } = req.body;
  // console.log(password, passwordConfirm);
  // 1. Hash the token from the URL
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

  // 2. Find user by hashed token and ensure it's not expired
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError('Token is invalid or has expired.', 400));
  }

  // 3. Set new password and clear reset fields
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 4. Log user in (send JWT)
  sendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token from cookie or Authorization header
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt; // ✅ support for cookie-based JWT
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log in to get access.', 401));
  }

  // 2) Verify token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user belonging to this token does no longer exist.', 401));
  }

  // 4) Check if user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('User recently changed password! Please log in again.', 401));
  }

  // ✅ Grant access
  req.user = currentUser;
  next();
});

//////// 8. Restrict Access /////////
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array like ['admin', 'owner']
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

///////////////////
exports.getMe = (req, res, next) => {
  req.params.id = req.user.id;
  next();
};

exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Create error if user POSTs password data
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError('This route is not for password updates. Please use /updateMyPassword.', 400)
    );
  }

  // 2) Filtered out unwanted fields names that are not allowed to be updated
  const filteredBody = {};
  const allowedFields = ['firstName', 'lastName', 'email', 'phoneNumber'];
  Object.keys(req.body).forEach((el) => {
    if (allowedFields.includes(el)) filteredBody[el] = req.body[el];
  });

  // 3) Update user document
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
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

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// const User = require('../models/User');
// const AppError = require('../utils/appError');
// const catchAsync = require('../utils/catchAsync');
// const jwt = require('jsonwebtoken');
// const { promisify } = require('util');
// const crypto = require('crypto');
// const sendEmail = require('../utils/email');
// const otpGenerator = require('../utils/otpGenerator');

// // Helper function to sign JWT
// const signToken = (user) => {
//   return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
//     expiresIn: process.env.JWT_EXPIRES_IN,
//   });
// };

// const sendToken = (user, statusCode, res) => {
//   const token = signToken(user);

//   const cookieOptions = {
//     expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
//     httpOnly: true,
//     secure: false, // allow for local HTTP dev
//     sameSite: 'Lax', // allows cross-origin cookies from same site over different port
//   };

//   if (process.env.NODE_ENV === 'production') {
//     cookieOptions.secure = true;
//     cookieOptions.sameSite = 'None';
//   }

//   res.cookie('jwt', token, cookieOptions);

//   user.password = undefined;
//   res.status(statusCode).json({
//     status: 'success',
//     token,
//     data: {
//       user,
//     },
//   });
// };

// // 1. Send OTP (updated Signup → now only sends OTP)
// exports.sendOTP = catchAsync(async (req, res, next) => {
//   const { email } = req.body;

//   if (!email) {
//     return next(new AppError('Please provide an email', 400));
//   }

//   // If user already exists, avoid duplicate accounts
//   const existingUser = await User.findOne({ email });
//   if (existingUser) {
//     return next(new AppError('Email already registered. Please login instead.', 400));
//   }

//   // Generate OTP
//   const otp = otpGenerator.generateOTP();

//   // Store OTP temporarily in User model (without creating user)
//   let tempUser = await User.findOne({ email }).select('+otp +otpExpires');

//   if (!tempUser) {
//     tempUser = new User({ email });
//   }

//   tempUser.otp = otp;
//   tempUser.otpExpires = Date.now() + 10 * 60 * 1000;
//   tempUser.isVerified = false;

//   await tempUser.save({ validateBeforeSave: false });

//   try {
//     await sendEmail(
//       email,
//       'Rentofix Verification OTP',
//       `<p>Your OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
//     );

//     res.status(200).json({
//       status: 'success',
//       message: 'OTP sent successfully!',
//     });
//   } catch (err) {
//     tempUser.otp = undefined;
//     tempUser.otpExpires = undefined;
//     await tempUser.save({ validateBeforeSave: false });

//     return next(new AppError('Failed to send email. Try again later!', 500));
//   }
// });

// // 2. Verify OTP (unchanged logic but no user creation)
// exports.verifyOTP = catchAsync(async (req, res, next) => {
//   const { email, otp } = req.body;

//   if (!email || !otp) {
//     return next(new AppError('Please provide email and OTP!', 400));
//   }

//   const user = await User.findOne({ email }).select('+otp +otpExpires');

//   if (!user) {
//     return next(new AppError('OTP request not found. Please request again.', 404));
//   }

//   if (!user.correctOtp(otp) || user.otpExpires < Date.now()) {
//     await User.deleteOne({ email }); // optional cleanup
//     return next(new AppError('Invalid or expired OTP. Please request again.', 400));
//   }

//   user.isVerified = true;
//   user.otp = undefined;
//   user.otpExpires = undefined;

//   await user.save({ validateBeforeSave: false });

//   res.status(200).json({
//     status: 'success',
//     message: 'OTP verified successfully!',
//   });
// });

// // 3. Create user only AFTER OTP verification
// exports.signup = catchAsync(async (req, res, next) => {
//   const { email } = req.body;

//   // User must be verified first
//   const tempUser = await User.findOne({ email });

//   if (!tempUser || !tempUser.isVerified) {
//     return next(new AppError('Please verify your email first!', 400));
//   }

//   // Now create real user
//   const newUser = await User.create({
//     firstName: req.body.firstName,
//     lastName: req.body.lastName,
//     email: email,
//     password: req.body.password,
//     passwordConfirm: req.body.passwordConfirm,
//     role: req.body.role || 'tenant',
//     phoneNumber: req.body.phoneNumber,
//     isVerified: true,
//   });

//   // Cleanup temporary record (optional)
//   await User.deleteOne({ email });

//   sendToken(newUser, 201, res);
// });

// exports.resendOTP = catchAsync(async (req, res, next) => {
//   const { email } = req.body;

//   if (!email) return next(new AppError('Please provide your email.', 400));

//   const user = await User.findOne({ email }).select('+otp +otpExpires');

//   if (!user) {
//     return next(new AppError('Email not found. Please request OTP first.', 404));
//   }

//   const otp = otpGenerator.generateOTP();
//   user.otp = otp;
//   user.otpExpires = Date.now() + 10 * 60 * 1000;

//   await user.save({ validateBeforeSave: false });

//   await sendEmail(
//     user.email,
//     'Rentofix - Resend OTP',
//     `<p>Your new OTP is <strong>${otp}</strong>. It will expire in 10 minutes.</p>`
//   );

//   res.status(200).json({
//     status: 'success',
//     message: 'New OTP sent!',
//   });
// });

// // 📂📂📂📂📂🗃️🗃️🗃️🗃️😎😎😎😎😎
// //////// 1. Signup /////////
// // exports.signup = catchAsync(async (req, res, next) => {
// //   const newUser = await User.create({
// //     firstName: req.body.firstName,
// //     lastName: req.body.lastName,
// //     email: req.body.email,
// //     password: req.body.password,
// //     passwordConfirm: req.body.passwordConfirm,
// //     role: req.body.role || 'tenant', // Default role
// //     phoneNumber: req.body.phoneNumber,
// //   });

// //   // Generate and send OTP for email verification
// //   const otp = otpGenerator.generateOTP();
// //   newUser.otp = otp;
// //   newUser.otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
// //   await newUser.save({ validateBeforeSave: false });

// //   try {
// //     await sendEmail(
// //       newUser.email,
// //       'Welcome to Rentofix',
// //       `<p>Your OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
// //     );
// //     res.status(201).json({
// //       status: 'success',
// //       message: 'OTP sent to email! Please verify your account.',
// //       data: {
// //         user: newUser,
// //       },
// //     });
// //   } catch (err) {
// //     newUser.otp = undefined;
// //     newUser.otpExpires = undefined;
// //     await newUser.save({ validateBeforeSave: false });
// //     return next(new AppError('There was an error sending the email. Try again later!', 500));
// //   }
// // });

// //////// 2. Login  //////////////
// exports.login = catchAsync(async (req, res, next) => {
//   const { email, password } = req.body;
//   // 1) Check if email and password exist
//   if (!email || !password) {
//     return next(new AppError('Please provide email and password!', 400));
//   }

//   // 2) Check if user exists && password is correct
//   const user = await User.findOne({ email }).select('+password');
//   if (!user || !(await user.correctPassword(password, user.password))) {
//     return next(new AppError('Incorrect email or password', 401));
//   }

//   // 3) If everything ok, send token to client
//   sendToken(user, 200, res);
// });

// //////// 3. VerifyOTP ///////////
// // exports.verifyOTP = catchAsync(async (req, res, next) => {
// //   const { email, otp } = req.body;

// //   if (!email || !otp) {
// //     return next(new AppError('Please provide email and OTP!', 400));
// //   }

// //   // 1. Find the user and include OTP fields
// //   const user = await User.findOne({ email }).select('+otp +otpExpires');

// //   // If no user found
// //   if (!user) {
// //     return next(new AppError('User not found.', 404));
// //   }

// //   // OTP invalid or expired
// //   if (!user.correctOtp(otp) || user.otpExpires < Date.now()) {
// //     // ❌ Delete the unverified user
// //     if (!user.isVerified) {
// //       await User.deleteOne({ email });
// //     }

// //     return next(new AppError('Invalid or expired OTP. Signup failed, please register again.', 400));
// //   }

// //   // 3. Mark user as verified
// //   user.isVerified = true;
// //   user.otp = undefined;
// //   user.otpExpires = undefined;
// //   await user.save({ validateBeforeSave: false });
// //   // 4. Send JWT token back
// //   sendToken(user, 200, res); // you must have sendToken(user, statusCode, res)
// // });

// //////// 4. ResendOTP /////////
// // exports.resendOTP = catchAsync(async (req, res, next) => {
// //   const { email } = req.body;

// //   if (!email) {
// //     return next(new AppError('Please provide your email.', 400));
// //   }

// //   const user = await User.findOne({ email }).select('+otp +otpExpires');

// //   if (!user) {
// //     return next(new AppError('No user found with that email address.', 404));
// //   }

// //   // Generate and assign new OTP
// //   const otp = otpGenerator.generateOTP();
// //   user.otp = otp;
// //   user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
// //   await user.save({ validateBeforeSave: false });

// //   try {
// //     await sendEmail(
// //       user.email,
// //       'Rentofix - Your New OTP',
// //       `
// //         <p>Hello ${user.firstName},</p>
// //         <p>Your new One-Time Password (OTP) is:</p>
// //         <h2>${otp}</h2>
// //         <p>This OTP is valid for the next 10 minutes.</p>
// //         <p>If you didn’t request this, please ignore this email.</p>
// //         <br/>
// //         <p>– Rentofix Team</p>
// //       `
// //     );

// //     res.status(200).json({
// //       status: 'success',
// //       message: 'New OTP sent to your email!',
// //     });
// //   } catch (err) {
// //     // Cleanup if sending fails
// //     user.otp = undefined;
// //     user.otpExpires = undefined;
// //     await user.save({ validateBeforeSave: false });

// //     return next(new AppError('Failed to send email. Please try again later.', 500));
// //   }
// // });

// //////// 5. ForgotPassword /////////
// // 5. Forgot Password
// exports.forgotPassword = catchAsync(async (req, res, next) => {
//   const { email } = req.body;

//   // 1. Check if email exists
//   if (!email) {
//     return next(new AppError('Please provide your email address.', 400));
//   }

//   // 2. Find user by email
//   const user = await User.findOne({ email });
//   if (!user) {
//     return next(new AppError('No user found with that email address.', 404));
//   }

//   // 3. Generate password reset token and save to DB
//   const resetToken = await user.createPasswordResetToken();
//   await user.save({ validateBeforeSave: false });
//   // console.log(process.env.FRONTEND_URL);
//   // 4. Create password reset URL
//   const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
//   // 4. Create password reset URL (pointing to React frontend)
//   // const resetURL = `http://localhost:3000/reset-password/${resetToken}`;

//   // 5. Construct email content
//   const emailHTML = `
//     <p>Hello ${user.firstName || 'User'},</p>
//     <p>You requested a password reset.</p>
//     <p>Click the link below to set a new password:</p>
//     <a href="${resetURL}" style="color: blue;">Reset Password</a>
//     <p>This link is valid for 10 minutes.</p>
//     <p>If you didn’t request this, just ignore this email.</p>
//     <br/>
//     <p>– Rentofix Team</p>
//   `;

//   // 6. Try to send email
//   try {
//     await sendEmail(user.email, 'Rentofix - Password Reset', emailHTML);

//     res.status(200).json({
//       status: 'success',
//       message: 'Password reset link sent to your email!',
//     });
//   } catch (err) {
//     // Cleanup if email fails
//     user.passwordResetToken = undefined;
//     user.passwordResetExpires = undefined;
//     await user.save({ validateBeforeSave: false });

//     return next(new AppError('Error sending email. Please try again later.', 500));
//   }
// });

// //////// 6. ResetPassword /////////
// exports.resetPassword = catchAsync(async (req, res, next) => {
//   console.log('hello', req.body);
//   const { password, passwordConfirm } = req.body;
//   // console.log(password, passwordConfirm);
//   // 1. Hash the token from the URL
//   const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

//   // 2. Find user by hashed token and ensure it's not expired
//   const user = await User.findOne({
//     passwordResetToken: hashedToken,
//     passwordResetExpires: { $gt: Date.now() },
//   });

//   if (!user) {
//     return next(new AppError('Token is invalid or has expired.', 400));
//   }

//   // 3. Set new password and clear reset fields
//   user.password = password;
//   user.passwordConfirm = passwordConfirm;
//   user.passwordResetToken = undefined;
//   user.passwordResetExpires = undefined;
//   await user.save();

//   // 4. Log user in (send JWT)
//   sendToken(user, 200, res);
// });

// exports.protect = catchAsync(async (req, res, next) => {
//   // 1) Getting token from cookie or Authorization header
//   let token;

//   if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
//     token = req.headers.authorization.split(' ')[1];
//   } else if (req.cookies && req.cookies.jwt) {
//     token = req.cookies.jwt; // ✅ support for cookie-based JWT
//   }

//   if (!token) {
//     return next(new AppError('You are not logged in! Please log in to get access.', 401));
//   }

//   // 2) Verify token
//   const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

//   // 3) Check if user still exists
//   const currentUser = await User.findById(decoded.id);
//   if (!currentUser) {
//     return next(new AppError('The user belonging to this token does no longer exist.', 401));
//   }

//   // 4) Check if user changed password after the token was issued
//   if (currentUser.changedPasswordAfter(decoded.iat)) {
//     return next(new AppError('User recently changed password! Please log in again.', 401));
//   }

//   // ✅ Grant access
//   req.user = currentUser;
//   next();
// });

// //////// 8. Restrict Access /////////
// exports.restrictTo = (...roles) => {
//   return (req, res, next) => {
//     // roles is an array like ['admin', 'owner']
//     if (!roles.includes(req.user.role)) {
//       return next(new AppError('You do not have permission to perform this action', 403));
//     }
//     next();
//   };
// };

// ///////////////////
// exports.getMe = (req, res, next) => {
//   req.params.id = req.user.id;
//   next();
// };

// exports.updateMe = catchAsync(async (req, res, next) => {
//   // 1) Create error if user POSTs password data
//   if (req.body.password || req.body.passwordConfirm) {
//     return next(
//       new AppError('This route is not for password updates. Please use /updateMyPassword.', 400)
//     );
//   }

//   // 2) Filtered out unwanted fields names that are not allowed to be updated
//   const filteredBody = {};
//   const allowedFields = ['firstName', 'lastName', 'email', 'phoneNumber'];
//   Object.keys(req.body).forEach((el) => {
//     if (allowedFields.includes(el)) filteredBody[el] = req.body[el];
//   });

//   // 3) Update user document
//   const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
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

// exports.deleteMe = catchAsync(async (req, res, next) => {
//   await User.findByIdAndUpdate(req.user.id, { active: false });

//   res.status(204).json({
//     status: 'success',
//     data: null,
//   });
// });
