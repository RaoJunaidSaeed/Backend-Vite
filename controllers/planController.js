const Plan = require('../models/Plan');
const factory = require('../utils/handlerFactory');
const catchAsync = require('../utils/catchAsync');

exports.getPlanById = factory.getOne(Plan);
exports.updatePlanById = factory.updateOne(Plan);
exports.deletePlanById = factory.deleteOne(Plan);
exports.createPlan = factory.createOne(Plan);

exports.getAllPlans = catchAsync(async (req, res) => {
  const plans = await Plan.find();

  res.status(200).json({
    status: 'success',
    results: plans.length,
    data: {
      plans,
    },
  });
});

// exports.getAllPlans = catchAsync(async (req, res) => {
//   const plans = await Plan.find({ isActive: true });

//   res.status(200).json({
//     status: 'success',
//     results: plans.length,
//     data: {
//       plans,
//     },
//   });
// });

const Payment = require('../models/Payment');

exports.getActivePlan = async (req, res) => {
  try {
    const payment = await Payment.findOne({
      ownerId: req.user._id,
      status: 'completed', // ensure only valid payments
      paymentType: 'listing_fee',
    })
      .sort({ paymentDate: -1 }) // latest first
      .populate('planId');

    res.status(200).json({
      status: 'success',
      data: {
        plan: payment?.planId || null,
      },
    });
  } catch (err) {
    console.error('Error fetching active plan:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to get active plan',
    });
  }
};
