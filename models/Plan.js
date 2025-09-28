const mongoose = require("mongoose");

const planSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "A plan must have a name"],
    unique: true,
    trim: true,
  },
  price: {
    type: Number,
    required: [true, "A plan must have a price"],
    min: [0, "Price must be positive"],
  },
  durationDays: {
    type: Number,
    required: [true, "A plan must have a duration in days"],
    min: [1, "Duration must be at least 1 day"],
  },
  maxListings: {
    type: Number,
    default: 1, // Default to 1 listing per plan
    min: [1, "Max listings must be at least 1"],
  },
  features: [String], // e.g., ["Featured Listing", "24/7 Support"]
  isActive: {
    type: Boolean,
    default: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: Date,
});

// Document middleware: runs before .save() and .create()
planSchema.pre("save", function (next) {
  this.updatedAt = Date.now();
  next();
});

const Plan = mongoose.model("Plan", planSchema);

module.exports = Plan;
