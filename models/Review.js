// models/reviewModel.js
const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema(
  {
    review: {
      type: String,
      required: [true, 'Review cannot be empty'],
      trim: true,
      minlength: [10, 'Review must be at least 10 characters long'],
      maxlength: [1000, 'Review must not exceed 1000 characters'],
    },
    rating: {
      type: Number,
      required: [true, 'Please provide a rating between 1 and 5'],
      min: [1, 'Rating must be at least 1'],
      max: [5, 'Rating cannot be more than 5'],
    },
    propertyId: {
      type: mongoose.Schema.ObjectId,
      ref: 'PropertyListing',
      required: [true, 'Review must belong to a property'],
    },
    tenantId: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Review must be written by a tenant'],
    },
    bookingId: {
      type: mongoose.Schema.ObjectId,
      ref: 'Booking', // assuming you have a Booking model
      required: [true, 'Review must be associated with a booking'],
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// 🛡️ Optional: Prevent duplicate reviews by the same tenant for the same property
// reviewSchema.index({ propertyId: 1, tenantId: 1 }, { unique: true });
reviewSchema.index({ bookingId: 1, tenantId: 1 }, { unique: true });

// Optional: auto-populate tenant info on find
reviewSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'tenantId',
    select: 'firstName lastName photo',
  });
  next();
});

module.exports = mongoose.model('Review', reviewSchema);
