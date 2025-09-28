const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
  ownerId: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Payment must be associated with an owner'],
  },
  planId: {
    type: mongoose.Schema.ObjectId,
    ref: 'Plan',
    required: [true, 'Payment must be associated with a plan'],
  },
  propertyIds: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'PropertyListing',
    },
  ],
  amount: {
    type: Number,
    required: [true, 'Payment must have an amount'],
    min: [0, 'Amount must be positive'],
  },
  currency: {
    type: String,
    default: 'PKR',
    enum: ['PKR', 'USD', 'EUR', 'GBP'],
  },
  paymentType: {
    type: String,
    required: [true, 'Payment must have a type'],
    enum: ['listing_fee', 'security_deposit', 'first_month_rent', 'platform_fee', 'other'],
  },
  transactionId: {
    type: String,
    unique: true,
    sparse: true,
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'refunded'],
    default: 'pending',
  },
  paymentDate: {
    type: Date,
    default: Date.now,
  },
  receiptUrl: String,
  verifiedByAdminId: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
  },
  verificationDate: Date,
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: Date,
});

// Middleware to update updatedAt timestamp
paymentSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Auto-populate on find queries
paymentSchema.pre(/^find/, function (next) {
  this.populate([
    {
      path: 'ownerId',
      select: 'firstName lastName email',
    },
    {
      path: 'propertyIds',
      select: 'title address region city',
    },
    {
      path: 'planId',
      select: 'price name durationDays features maxListings',
    },
  ]);
  next();
});

const Payment = mongoose.model('Payment', paymentSchema);

module.exports = Payment;
