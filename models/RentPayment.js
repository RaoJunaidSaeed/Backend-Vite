const mongoose = require('mongoose');

const rentPaymentSchema = new mongoose.Schema({
  tenantId: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Rent payment must be associated with a tenant'],
  },
  ownerId: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Rent payment must be associated with an owner'],
  },
  propertyId: {
    type: mongoose.Schema.ObjectId,
    ref: 'PropertyListing',
    required: [true, 'Rent payment must be associated with a property'],
  },
  amount: {
    type: Number,
    required: [true, 'Rent payment must have an amount'],
    min: [0, 'Amount must be positive'],
  },
  currency: {
    type: String,
    default: 'PKR',
    enum: ['PKR', 'USD', 'EUR', 'GBP'],
  },
  paymentPeriod: {
    type: String,
    required: [true, "Rent payment must have a payment period (e.g., 'January 2025')"],
  },
  dueDate: {
    type: Date,
    required: [true, 'Rent payment must have a due date'],
  },
  paymentDate: {
    type: Date,
    default: Date.now,
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'overdue'],
    default: 'pending',
  },
  transactionId: {
    type: String,
    unique: true,
    sparse: true,
  },
  receiptUrl: String,
  verifiedByOwnerId: {
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
rentPaymentSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Auto-populate on find queries
rentPaymentSchema.pre(/^find/, function (next) {
  this.populate([
    {
      path: 'tenantId',
      select: 'firstName lastName email',
    },
    {
      path: 'ownerId',
      select: 'firstName lastName email',
    },
    {
      path: 'propertyId',
      select: 'title address region city',
    },
  ]);
  next();
});

const RentPayment = mongoose.model('RentPayment', rentPaymentSchema);

module.exports = RentPayment;
