const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please tell us your first name!'],
  },
  lastName: {
    type: String,
    required: [true, 'Please tell us your last name!'],
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },
  phoneNumber: {
    type: String,
    unique: true,
    sparse: true, // Allows null values to not violate unique constraint
    validate: {
      validator: function (el) {
        return validator.isMobilePhone(el, 'any');
      },
      message: 'Please provide a valid phone number',
    },
  },
  role: {
    type: String,
    enum: ['tenant', 'owner', 'admin'],
    default: 'tenant',
  },
  photo: {
    type: String,
    default:
      'https://res.cloudinary.com/dcmld4ryz/image/upload/v1761499242/user-profile-image_fphdf0.png', // Optional fallback
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false, // Don't send password in query results by default
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // This only works on CREATE and SAVE!!!
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!',
    },
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
  otp: String, // For OTP verification
  otpExpires: Date, // For OTP expiration
  isVerified: {
    type: Boolean,
    default: false,
  },
});

// Encrypt password before saving
userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

// Update passwordChangedAt property for the user
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000; // -1s to ensure token is always created after password change
  next();
});

// Query middleware to only find active users
userSchema.pre(/^find/, function (next) {
  // 'this' points to the current query
  this.find({ active: { $ne: false } });
  next();
});

// Instance method to compare passwords
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Compare OTPs securely
userSchema.methods.correctOtp = function (candidateOtp) {
  return this.otp === candidateOtp; // You can enhance this with crypto timingSafeEqual for more security
};

// Instance method to check if password was changed after token was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  // False means NOT changed
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;

// Virtual populate rent payments
userSchema.virtual('rentPayments', {
  ref: 'RentPayment',
  foreignField: 'tenantId',
  localField: '_id',
});

userSchema.virtual('ownedRentPayments', {
  ref: 'RentPayment',
  foreignField: 'ownerId',
  localField: '_id',
});
