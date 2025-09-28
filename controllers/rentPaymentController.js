const RentPayment = require('../models/RentPayment');
const PropertyListing = require('../models/PropertyListing');
const User = require('../models/User');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const handlerFactory = require('../utils/handlerFactory');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.createRentPaymentIntent = catchAsync(async (req, res, next) => {
  const { propertyId, amount, currency, paymentPeriod, dueDate } = req.body;

  if (!propertyId || !amount) {
    return next(new AppError('Property ID and amount are required', 400));
  }

  const property = await PropertyListing.findById(propertyId);
  if (!property) {
    return next(new AppError('Property not found', 404));
  }

  const paymentIntent = await stripe.paymentIntents.create({
    amount: amount * 100,
    currency: currency || 'pkr',
    metadata: {
      propertyId,
      tenantId: req.user.id,
      paymentPeriod,
      dueDate,
    },
  });

  res.status(200).json({
    status: 'success',
    clientSecret: paymentIntent.client_secret,
  });
});

// Tenant initiates a rent payment
exports.initiateRentPayment = catchAsync(async (req, res, next) => {
  const { propertyId, amount, paymentPeriod, dueDate, transactionId } = req.body;
  const tenantId = req.user.id;

  // Verify property exists and get owner
  const property = await PropertyListing.findById(propertyId);
  if (!property) {
    return next(new AppError('Property not found', 404));
  }

  // Check if payment for this period already exists
  const existingPayment = await RentPayment.findOne({
    tenantId,
    propertyId,
    paymentPeriod,
  });

  if (existingPayment) {
    return next(new AppError('Payment for this period already exists', 400));
  }

  // Create rent payment
  const rentPayment = await RentPayment.create({
    tenantId,
    ownerId: property.ownerId,
    propertyId,
    amount,
    paymentPeriod,
    dueDate,
    transactionId,
    status: 'completed', // Assuming payment is completed when initiated
  });

  res.status(201).json({
    status: 'success',
    data: {
      rentPayment,
    },
  });
});

// Get tenant's payment history
exports.getTenantPaymentHistory = catchAsync(async (req, res, next) => {
  const tenantId = req.user.id;

  const payments = await RentPayment.find({ tenantId }).sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    results: payments.length,
    data: {
      payments,
    },
  });
});

exports.getTenantPropertyPayment = catchAsync(async (req, res, next) => {
  const { propertyId } = req.params;
  const tenantId = req.user.id;

  const payment = await RentPayment.findOne({ propertyId, tenantId });

  if (!payment) {
    return res.status(200).json({ status: 'unpaid' });
  }

  res.status(200).json({
    status: 'success',
    data: { payment },
  });
});

// Get payment history for a specific property (owner only)
exports.getPropertyPaymentHistory = catchAsync(async (req, res, next) => {
  const { propertyId } = req.params;
  const ownerId = req.user.id;

  // Verify property belongs to the owner
  const property = await PropertyListing.findOne({ _id: propertyId, ownerId });
  if (!property) {
    return next(new AppError("Property not found or you don't have access", 404));
  }

  const payments = await RentPayment.find({ propertyId }).sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    results: payments.length,
    data: {
      payments,
    },
  });
});

// Owner verifies a rent payment
exports.verifyRentPayment = catchAsync(async (req, res, next) => {
  const { paymentId } = req.params;
  const ownerId = req.user.id;

  // Find payment and verify owner has access
  const payment = await RentPayment.findOne({ _id: paymentId, ownerId });
  if (!payment) {
    return next(new AppError("Payment not found or you don't have access", 404));
  }

  // Update payment verification
  payment.verifiedByOwnerId = ownerId;
  payment.verificationDate = new Date();
  await payment.save();

  res.status(200).json({
    status: 'success',
    data: {
      payment,
    },
  });
});

// Get all payments for owner's properties
exports.getOwnerPaymentHistory = catchAsync(async (req, res, next) => {
  const ownerId = req.user.id;

  const payments = await RentPayment.find({ ownerId }).sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    results: payments.length,
    data: {
      payments,
    },
  });
});

exports.checkRentPaymentStatus = async (req, res) => {
  try {
    const { propertyId, tenantId } = req.params;

    const now = new Date();
    const currentMonth = now.toLocaleString('default', { month: 'long' });
    const currentYear = now.getFullYear();
    const paymentPeriod = `${currentMonth} ${currentYear}`;

    const existingPayment = await RentPayment.findOne({
      propertyId,
      tenantId,
      paymentPeriod,
      status: 'completed',
    });

    res.status(200).json({
      alreadyPaid: !!existingPayment,
      payment: existingPayment,
    });
  } catch (err) {
    console.error('Error checking rent payment:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Admin functions using handlerFactory
exports.getAllRentPayments = handlerFactory.getAll(RentPayment);
exports.getRentPaymentById = handlerFactory.getOne(RentPayment);
exports.updateRentPaymentById = handlerFactory.updateOne(RentPayment);
exports.deleteRentPaymentById = handlerFactory.deleteOne(RentPayment);
