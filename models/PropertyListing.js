const mongoose = require('mongoose');
const Review = require('./Review');
const validator = require('validator');

const propertyListingSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'A property must have a title'],
      trim: true,
      maxlength: [100, 'A property title must have less or equal than 100 characters'],
      minlength: [10, 'A property title must have more or equal than 10 characters'],
    },
    description: {
      type: String,
      required: [true, 'A property must have a description'],
      trim: true,
    },
    address: {
      type: String,
      required: [true, 'A property must have an address'],
      trim: true,
    },
    city: {
      type: String,
      required: [true, 'A property must have a city'],
      trim: true,
      default: 'Sahiwal',
    },
    region: {
      type: String,
      required: [true, 'A property must have a region'],
      trim: true,
      default: 'Pak Pattan Chowk',
    },
    propertyType: {
      type: String,
      required: [true, 'A property must have a type'],
      enum: ['house', 'office', 'shop'],
      message: 'Property type is either: house, office, shop',
    },
    rentAmount: {
      type: Number,
      required: [true, 'A property must have a rent amount'],
      min: [0, 'Rent amount must be positive'],
    },
    currency: {
      type: String,
      default: 'PKR',
      enum: ['PKR', 'USD', 'EUR', 'GBP'],
    },
    numberOfBedrooms: Number,
    numberOfBathrooms: Number,
    areaSqFt: Number,
    amenities: [String], // Array of strings, e.g., ["parking", "AC", "furnished"]
    images: {
      type: [String],
      validate: {
        validator: function (val) {
          return val.length <= 5;
        },
        message: 'You can upload a maximum of 5 images per property.',
      },
    },
    availabilityStatus: {
      type: String,
      enum: ['available', 'rented', 'pending'],
      default: 'available',
    },
    isVerified: {
      type: Boolean,
      default: false, // Set by admin after verification
    },
    isActive: {
      type: Boolean,
      default: true, // Can be deactivated by owner or admin
    },
    ownerId: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Property must belong to a user (owner)'],
    },
    planId: {
      type: mongoose.Schema.ObjectId,
      ref: 'Plan',
      required: [true, 'Property must be associated with a plan'],
    },
    expiresAt: Date, // Calculated based on plan duration
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: Date,
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Index for efficient searching
propertyListingSchema.index({ rentAmount: 1, city: 1 });
propertyListingSchema.index({ dealerId: 1 });
propertyListingSchema.index({ address: 1, city: 1, region: 1 }, { unique: true });

// Virtual populate reviews
propertyListingSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'propertyId',
  localField: '_id',
});

// Document middleware: runs before .save() and .create()
propertyListingSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

const PropertyListing = mongoose.model('PropertyListing', propertyListingSchema);

module.exports = PropertyListing;


// Virtual populate rent payments
propertyListingSchema.virtual("rentPayments", {
  ref: "RentPayment",
  foreignField: "propertyId",
  localField: "_id",
});


