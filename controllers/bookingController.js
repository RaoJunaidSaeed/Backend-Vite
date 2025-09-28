const Booking = require('../models/Booking');
const PropertyListing = require('../models/PropertyListing');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const factory = require('../utils/handlerFactory');

exports.getAllBookings = factory.getAll(Booking);
exports.updateBooking = factory.updateOne(Booking);
exports.deleteBooking = factory.deleteOne(Booking);
exports.getBooking = factory.getOne(Booking, {
  path: 'propertyId tenantId ownerId',
});

exports.createBooking = catchAsync(async (req, res, next) => {
  const { desiredMoveInDate, desiredLeaseDuration, messageFromTenant } = req.body;
  const { propertyId } = req.params;

  // Ensure the user is verified and a tenant
  if (req.user.role !== 'tenant') {
    return next(new AppError('Only tenants can create bookings', 403));
  }

  if (!req.user.isVerified) {
    return next(new AppError('Please verify your account via OTP before booking', 401));
  }

  // Fetch property to get owner
  const property = await PropertyListing.findById(propertyId);
  if (!property || property.availabilityStatus !== 'available') {
    return next(new AppError('Property is not available', 404));
  }

  // Prevent user from booking their own property
  if (String(property.ownerId) === String(req.user._id)) {
    return next(new AppError('You cannot book your own property', 400));
  }

  // Prevent duplicate booking
  const existingBooking = await Booking.findOne({
    tenantId: req.user._id,
    propertyId,
    status: { $in: ['pending', 'approved'] },
  });

  if (existingBooking) {
    return next(new AppError('You already have a pending/approved booking for this property', 400));
  }

  // Create new booking (status = pending by default)
  const newBooking = await Booking.create({
    tenantId: req.user._id,
    ownerId: property.ownerId,
    propertyId,
    desiredMoveInDate,
    desiredLeaseDuration,
    messageFromTenant,
  });

  // Only populate non-sensitive fields for now
  let booking = await Booking.findById(newBooking._id).populate([
    { path: 'propertyId', select: 'title address rentAmount images' },
    { path: 'tenantId', select: 'firstName lastName email phoneNumber' },
    { path: 'ownerId', select: 'firstName lastName email phoneNumber' },
  ]);

  booking = booking.toObject();

  // Sanitize contact info
  if (!booking.contactInfoShared) {
    // Hide tenant's contact from owner
    if (req.user.role === 'owner' && booking.tenantId) {
      booking.tenantId.email = undefined;
      booking.tenantId.phoneNumber = undefined;
    }

    // Hide owner's contact from tenant
    if (req.user.role === 'tenant' && booking.ownerId) {
      booking.ownerId.email = undefined;
      booking.ownerId.phoneNumber = undefined;
    }
  }

  res.status(201).json({
    status: 'success',
    data: { booking },
  });
});

exports.getMyBookingsOrRequests = catchAsync(async (req, res, next) => {
  let populateFields = [
    { path: 'propertyId', select: 'title address region city rentAmount images' },
  ];

  // Conditionally populate owner or tenant info
  if (req.user.role === 'tenant') {
    populateFields.push({
      path: 'ownerId',
      select: 'firstName lastName email phoneNumber',
    });
  } else if (req.user.role === 'owner') {
    populateFields.push({
      path: 'tenantId',
      select: 'firstName lastName email phoneNumber',
    });
  }

  // Fetch bookings based on the role
  const bookings = await Booking.find({
    [req.user.role === 'tenant' ? 'tenantId' : 'ownerId']: req.user.id,
  }).populate(populateFields);

  res.status(200).json({
    status: 'success',
    results: bookings.length,
    data: {
      bookings,
    },
  });
});

exports.getMyBookingForProperty = catchAsync(async (req, res, next) => {
  const { propertyId } = req.params;
  const tenantId = req.user._id;

  const booking = await Booking.findOne({ propertyId, tenantId });

  if (!booking) {
    return next(new AppError('No booking found for this property', 404));
  }

  const response = {
    status: booking.status,
    contactInfoShared: booking.contactInfoShared,
  };

  if (booking.status === 'approved' && booking.contactInfoShared) {
    const owner = await require('../models/User')
      .findById(booking.ownerId)
      .select('firstName lastName email phoneNumber');

    response.ownerName = `${owner.firstName} ${owner.lastName}`;
    response.ownerEmail = owner.email;
    response.ownerPhone = owner.phoneNumber;
  }

  res.status(200).json({
    status: 'success',
    data: response,
  });
});

// exports.getMyBookingsOrRequests = catchAsync(async (req, res, next) => {
//   let populateFields = [{ path: 'propertyId', select: 'title address rentAmount images' }];

//   // Conditionally populate owner or tenant info
//   if (req.user.role === 'tenant') {
//     populateFields.push({
//       path: 'ownerId',
//       select: 'firstName lastName email phoneNumber',
//     });
//   } else if (req.user.role === 'owner') {
//     populateFields.push({
//       path: 'tenantId',
//       select: 'firstName lastName email phoneNumber',
//     });
//   }

//   const bookings = await Booking.find({
//     [req.user.role === 'tenant' ? 'tenantId' : 'ownerId']: req.user.id,
//   }).populate(populateFields);

//   // Mask contact info if not shared
//   const sanitizedBookings = bookings.map((booking) => {
//     const sanitized = booking.toObject();

//     if (!booking.contactInfoShared) {
//       if (req.user.role === 'tenant' && sanitized.ownerId) {
//         // sanitized.ownerId.email = undefined;
//         sanitized.ownerId.phoneNumber = undefined;
//       } else if (req.user.role === 'owner' && sanitized.tenantId) {
//         // sanitized.tenantId.email = undefined;
//         sanitized.tenantId.phoneNumber = undefined;
//       }
//     }

//     return sanitized;
//   });

//   res.status(200).json({
//     status: 'success',
//     results: sanitizedBookings.length,
//     data: {
//       bookings: sanitizedBookings,
//     },
//   });
// });

// Approve a booking
exports.approveBooking = catchAsync(async (req, res, next) => {
  const booking = await Booking.findById(req.params.id).populate('ownerId');

  if (!booking) {
    return next(new AppError('Booking not found', 404));
  }

  if (booking.ownerId._id.toString() !== req.user._id.toString()) {
    return next(new AppError('You are not allowed to approve this booking', 403));
  }

  if (booking.status !== 'pending') {
    return next(new AppError('Only pending bookings can be approved', 400));
  }

  // ✅ Approve and share contact info
  booking.status = 'approved';
  booking.contactInfoShared = true;
  await booking.save();

  // console.log('😎', booking.propertyId._id, '😎');
  const propertyId = booking.propertyId._id || booking.propertyId;
  // console.log(propertyId);

  const res1 = await PropertyListing.findByIdAndUpdate(
    propertyId,
    { availabilityStatus: 'rented' },
    { new: true }
  );

  // ✅ Populate all related info to show in response
  const updatedBooking = await Booking.findById(booking._id).populate([
    {
      path: 'propertyId',
      select: 'title address rentAmount images',
    },
    {
      path: 'tenantId',
      select: 'firstName lastName email phoneNumber',
    },
    {
      path: 'ownerId',
      select: 'firstName lastName email phoneNumber',
    },
  ]);

  res.status(200).json({
    status: 'success',
    data: { booking: updatedBooking },
  });
});

exports.rejectBooking = catchAsync(async (req, res, next) => {
  const booking = await Booking.findById(req.params.id).populate('ownerId');

  if (!booking) {
    return next(new AppError('Booking not found', 404));
  }

  if (booking.ownerId._id.toString() !== req.user._id.toString()) {
    return next(new AppError('You are not allowed to reject this booking', 403));
  }

  if (booking.status !== 'pending') {
    return next(new AppError('Only pending bookings can be rejected', 400));
  }

  // ❌ Do NOT share contact info
  booking.status = 'rejected';
  booking.contactInfoShared = false;
  await booking.save();

  res.status(200).json({
    status: 'success',
    message: 'Booking rejected successfully',
    data: {
      booking: {
        _id: booking._id,
        status: booking.status,
        requestDate: booking.requestDate,
        propertyId: booking.propertyId,
      },
    },
  });
});

exports.updateBookingStatus = catchAsync(async (req, res, next) => {
  const { id } = req.params;
  const { status } = req.body;

  const validStatuses = ['pending', 'approved', 'rejected'];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid status provided',
    });
  }

  const booking = await Booking.findById(id);

  if (!booking) {
    return res.status(404).json({
      status: 'fail',
      message: 'Booking not found',
    });
  }

  booking.status = status;
  await booking.save();
  // console.log(booking);
  res.status(200).json({
    status: 'success',
    message: `Booking status updated to ${status}`,
    data: {
      booking,
    },
  });
});
