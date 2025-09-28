const Review = require('../models/Review');
const Booking = require('../models/Booking');
const PropertyListing = require('../models/PropertyListing');

const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('../utils/handlerFactory');

exports.getAllReviews = factory.getAll(Review);
exports.updateReview = factory.updateOne(Review);
exports.deleteReview = factory.deleteOne(Review);
exports.getReview = factory.getOne(Review, {
  path: 'propertyId tenantId bookingId',
});

exports.createReview = catchAsync(async (req, res, next) => {
  const propertyId = req.body.propertyId || req.params.propertyId;
  const tenantId = req.user.id;

  // Find an approved booking for this tenant and property
  const booking = await Booking.findOne({
    tenantId,
    propertyId,
    status: 'approved',
  });

  if (!booking) {
    return next(new AppError('No approved booking found for this tenant and property.', 400));
  }

  // 🔄 Check if this booking has already been reviewed
  const existingReview = await Review.findOne({
    tenantId,
    bookingId: booking._id, // now based on bookingId, not just propertyId
  });

  if (existingReview) {
    return next(new AppError('You have already submitted a review for this booking.', 400));
  }

  // Attach required fields to request
  req.body.propertyId = propertyId;
  req.body.tenantId = tenantId;
  req.body.bookingId = booking._id;

  console.log(req.body);
  const newReview = await Review.create(req.body);
  console.log(newReview);
  res.status(201).json({
    status: 'success',
    data: {
      review: newReview,
    },
  });
});

exports.getReviewsByProperty = catchAsync(async (req, res, next) => {
  const propertyId = req.params.propertyId;

  const reviews = await Review.find({ propertyId })
    .populate('propertyId', 'title address')
    .populate('tenantId', 'firstName lastName')
    .populate('bookingId', 'status messageFromTenant');

  res.status(200).json({
    status: 'success',
    results: reviews.length,
    data: {
      reviews,
    },
  });
});
