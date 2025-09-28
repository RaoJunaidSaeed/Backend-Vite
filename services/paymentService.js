const Payment = require("../models/Payment");
const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

exports.createPaymentIntent = catchAsync(async (amount, currency, description) => {
  const paymentIntent = await stripe.paymentIntents.create({
    amount: amount * 100, // Stripe expects amount in cents
    currency,
    description,
  });
  return paymentIntent;
});

exports.recordPayment = async (paymentData) => {
  const newPayment = await Payment.create(paymentData);
  return newPayment;
};

exports.updatePaymentStatus = async (transactionId, status, verifiedByAdminId = null) => {
  const payment = await Payment.findOneAndUpdate(
    { transactionId },
    { status, verifiedByAdminId, verificationDate: Date.now() },
    { new: true, runValidators: true }
  );
  if (!payment) {
    throw new AppError("Payment not found", 404);
  }
  return payment;
};

exports.getPaymentById = async (id) => {
  const payment = await Payment.findById(id);
  if (!payment) {
    throw new AppError("Payment not found", 404);
  }
  return payment;
};

exports.getAllPayments = async () => {
  const payments = await Payment.find();
  return payments;
};


