const PropertyListing = require('../models/PropertyListing');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const Plan = require('../models/Plan');
const Payment = require('../models/Payment');
const factory = require('../utils/handlerFactory');
const { cloudinary } = require('../utils/cloudinary');

exports.getAllProperties = factory.getAll(PropertyListing);
// exports.updateProperty = factory.updateOne(PropertyListing);
exports.deleteProperty = factory.deleteOne(PropertyListing);
exports.getOneProperty = factory.getOne(PropertyListing, [
  { path: 'reviews' },
  { path: 'planId' },
  { path: 'ownerId', select: 'firstName lastName email phoneNumber role' },
]);

exports.createProperty = catchAsync(async (req, res, next) => {
  if (!req.user || !req.user.id) {
    return next(new AppError('User not authenticated.', 401));
  }

  // Always set ownerId from session, not client input
  delete req.body.ownerId;
  req.body.ownerId = req.user.id;

  // Verify valid completed payment
  const latestPayment = await Payment.findOne({
    ownerId: req.user.id,
    paymentType: 'listing_fee',
    status: 'completed',
  }).sort({ createdAt: -1 });

  if (!latestPayment) {
    return next(
      new AppError('No valid active paid plan found. Please purchase a plan first.', 403)
    );
  }

  const plan = await Plan.findById(latestPayment.planId);
  if (!plan || !plan.isActive) {
    return next(new AppError('The plan in your payment is no longer active.', 403));
  }

  const currentListings = await PropertyListing.countDocuments({
    ownerId: req.user.id,
    planId: plan._id,
    isActive: true,
  });

  const maxAllowed = plan.maxListings ?? 0;
  if (currentListings >= maxAllowed) {
    return next(
      new AppError(
        `You have reached your listing limit (${maxAllowed}) for the ${plan.name} plan.`,
        403
      )
    );
  }

  // Set plan-related metadata
  req.body.planId = plan._id;
  req.body.expiresAt = new Date(Date.now() + plan.durationDays * 24 * 60 * 60 * 1000);

  // Handle Cloudinary image uploads
  if (req.files && req.files.length > 0) {
    // req.body.images = req.files.map((file) => ({
    //   url: file.path,
    //   public_id: file.filename,
    // }));
    req.body.images = req.files.map((file) => file.path);
  }

  // Create the property
  const newProperty = await PropertyListing.create(req.body);

  // Link to payment
  latestPayment.propertyIds.push(newProperty._id);
  await latestPayment.save();

  res.status(201).json({
    status: 'success',
    data: {
      property: newProperty,
    },
  });
});

exports.updateProperty = catchAsync(async (req, res, next) => {
  const propertyId = req.params.id;

  const existingProperty = await PropertyListing.findById(propertyId);
  if (!existingProperty) {
    return next(new AppError('Property not found', 404));
  }

  // If new images are uploaded, append them to existing ones
  if (req.files && req.files.length > 0) {
    // const newImages = req.files.map((file) => ({
    //   url: file.path,
    //   public_id: file.filename,
    // }));
    req.body.images = req.files.map((file) => file.path);

    req.body.images = [...(existingProperty.images || []), ...newImages];
  }

  const updatedProperty = await PropertyListing.findByIdAndUpdate(propertyId, req.body, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: 'success',
    data: {
      property: updatedProperty,
    },
  });
});

// exports.createProperty = catchAsync(async (req, res, next) => {
//   // Ensure user is authenticated
//   if (!req.user || !req.user.id) {
//     return next(new AppError('User not authenticated.', 401));
//   }

//   // Remove any injected ownerId from request
//   delete req.body.ownerId;
//   req.body.ownerId = req.user.id;

//   // Find latest completed payment
//   const latestPayment = await Payment.findOne({
//     ownerId: req.user.id,
//     paymentType: 'listing_fee',
//     status: 'completed',
//   }).sort({ createdAt: -1 });

//   if (!latestPayment) {
//     return next(
//       new AppError('No valid active paid plan found. Please purchase a plan first.', 403)
//     );
//   }

//   // Fetch the plan manually
//   const plan = await Plan.findById(latestPayment.planId);

//   if (!plan || !plan.isActive) {
//     return next(new AppError('The plan in your payment is no longer active.', 403));
//   }

//   // Count how many properties have been linked to this payment
//   const currentListings = await PropertyListing.countDocuments({
//     ownerId: req.user.id,
//     planId: plan._id,
//     isActive: true,
//   });

//   const maxAllowed = plan.maxListings ?? 0;

//   if (currentListings >= maxAllowed) {
//     return next(
//       new AppError(
//         `You have reached your listing limit (${maxAllowed}) for the ${plan.name} plan.`,
//         403
//       )
//     );
//   }

//   // Set required fields for the property
//   req.body.planId = plan._id;
//   req.body.expiresAt = new Date(Date.now() + plan.durationDays * 24 * 60 * 60 * 1000);

//   if (req.files && req.files.length > 0) {
//     const BASE_URL = `${req.protocol}://${req.get('host')}`;
//     req.body.images = req.files.map((file) => `${BASE_URL}/uploads/${file.filename}`);
//   }

//   // Create the property
//   const newProperty = await PropertyListing.create(req.body);

//   // Attach this property to the payment record
//   latestPayment.propertyIds.push(newProperty._id);
//   await latestPayment.save();

//   // Respond with success
//   res.status(201).json({
//     status: 'success',
//     data: {
//       property: newProperty,
//     },
//   });
// });

// exports.updateProperty = catchAsync(async (req, res, next) => {
//   const propertyId = req.params.id;

//   // Find the existing property
//   const existingProperty = await PropertyListing.findById(propertyId);
//   if (!existingProperty) {
//     return next(new AppError('Property not found', 404));
//   }

//   if (req.files && req.files.length > 0) {
//     const BASE_URL = `${req.protocol}://${req.get('host')}`;
//     const newImagePaths = req.files.map((file) => `${BASE_URL}/uploads/${file.filename}`);
//     req.body.images = [...(existingProperty.images || []), ...newImagePaths];
//   }

//   // Perform the update
//   const updatedProperty = await PropertyListing.findByIdAndUpdate(propertyId, req.body, {
//     new: true,
//     runValidators: true,
//   });

//   res.status(200).json({
//     status: 'success',
//     data: {
//       property: updatedProperty,
//     },
//   });
// });

exports.getOwnerProperties = catchAsync(async (req, res, next) => {
  // console.log('📥 Incoming GET /properties request');
  // console.log('Cookies:', req.cookies); // If using cookies
  // console.log('User:', req.user);
  const ownerProperties = await PropertyListing.find({
    ownerId: req.user.id,
  }).populate('planId');

  res.status(200).json({
    status: 'success',
    results: ownerProperties.length,
    data: {
      properties: ownerProperties,
    },
  });
});

exports.verifyProperty = catchAsync(async (req, res, next) => {
  const property = await PropertyListing.findByIdAndUpdate(
    req.params.id,
    { isVerified: true },
    { new: true }
  );

  res.status(200).json({
    status: 'success',
    data: { property },
  });
});
