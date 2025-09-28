const Payment = require("../models/Payment");
const Plan = require("../models/Plan");
const User = require("../models/User");

const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const factory = require("../utils/handlerFactory");

exports.getAllPayment = factory.getAll(Payment);
exports.getPaymentById = factory.getOne(Payment);
exports.updatePaymentById = factory.updateOne(Payment);
exports.deletePaymentById = factory.deleteOne(Payment);

exports.createPaymentIntent = catchAsync(async (req, res, next) => {
  const { planId, currency } = req.body;

  // 1. Validate
  if (!planId) {
    return next(new AppError("Plan ID is required", 400));
  }

  // 2. Find plan and verify price
  const plan = await Plan.findById(planId);
  if (!plan) {
    return next(new AppError("Plan not found", 404));
  }

  // 3. Create payment intent on Stripe
  const paymentIntent = await stripe.paymentIntents.create({
    amount: plan.price * 100, // Stripe expects amount in cents/paisa
    currency: currency || "pkr",
    metadata: { planId: plan._id.toString() },
  });

  // 4. Send client secret to frontend
  res.status(200).json({
    status: "success",
    clientSecret: paymentIntent.client_secret,
  });
});

exports.createPayment = catchAsync(async (req, res, next) => {
  const { transactionId, amount, currency, paymentType } = req.body;
  const planId = req.params.planId;
  const ownerId = req.user.id; // Automatically extracted from logged-in user

  // 1️⃣ Validate required fields
  if (!planId || !transactionId || !amount) {
    return next(new AppError("Missing required payment fields", 400));
  }

  // 2️⃣ Check that user is an owner
  // const owner = await User.findOne({ _id: ownerId, role: "owner" });
  // if (!owner) {
  //   return next(
  //     new AppError("Only users with role 'owner' can make this payment", 403)
  //   );
  // }

  // 3️⃣ Fetch and validate plan
  const plan = await Plan.findById(planId);
  if (!plan) {
    return next(new AppError("Plan not found", 404));
  }

  // 4️⃣ Ensure amount matches plan price
  if (amount !== plan.price) {
    return next(new AppError("Payment amount does not match plan price", 400));
  }

  // 5️⃣ Create payment
  const payment = await Payment.create({
    ownerId,
    planId,
    amount,
    currency: currency || "PKR",
    paymentType: paymentType || "listing_fee",
    transactionId,
    status: "completed",
  });

  // 6️⃣ Populate and respond
  const populatedPayment = await Payment.findById(payment._id)
    .populate("ownerId", "firstName lastName email")
    .populate("planId", "name price durationDays maxListings");

  res.status(201).json({
    status: "success",
    data: { payment: populatedPayment },
  });
});
