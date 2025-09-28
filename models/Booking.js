const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  propertyId: {
    type: mongoose.Schema.ObjectId,
    ref: 'PropertyListing',
    required: [true, 'Booking must belong to a property'],
  },
  tenantId: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Booking must belong to a tenant'],
  },
  ownerId: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Booking must be associated with an owner'],
  },
  requestDate: {
    type: Date,
    default: Date.now,
  },
  desiredMoveInDate: {
    type: Date,
    required: [true, 'Please provide a desired move-in date'],
  },
  desiredLeaseDuration: {
    type: String,
    enum: ['3 months', '6 months', '1 year', '2 years', 'flexible'],
    default: '1 year',
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'cancelled', 'completed'],
    default: 'pending',
  },
  messageFromTenant: String,
  messageFromOwner: String,
  contactInfoShared: {
    type: Boolean,
    default: false, // Set to true once owner approves and shares contact
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: Date,
});

// Document middleware: runs before .save() and .create()
bookingSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Populate property, tenant, and owner details on find
bookingSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'propertyId',
    select: 'title address region city rentAmount images',
  })
    .populate({
      path: 'tenantId',
      select: 'firstName lastName email phoneNumber',
    })
    .populate({
      path: 'ownerId',
      select: 'firstName lastName email phoneNumber',
    });
  next();
});

const Booking = mongoose.model('Booking', bookingSchema);

module.exports = Booking;
