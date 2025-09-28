const Review = require("../models/Review");
const AppError = require("../utils/appError");

exports.createReview = async (reviewData) => {
  const newReview = await Review.create(reviewData);
  return newReview;
};

exports.getAllReviews = async (filter) => {
  const reviews = await Review.find(filter);
  return reviews;
};

exports.getReviewById = async (id) => {
  const review = await Review.findById(id);
  if (!review) {
    throw new AppError("No review found with that ID", 404);
  }
  return review;
};

exports.updateReview = async (id, updateData) => {
  const review = await Review.findByIdAndUpdate(id, updateData, {
    new: true,
    runValidators: true,
  });
  if (!review) {
    throw new AppError("No review found with that ID", 404);
  }
  return review;
};

exports.deleteReview = async (id) => {
  const review = await Review.findByIdAndDelete(id);
  if (!review) {
    throw new AppError("No review found with that ID", 404);
  }
  return null;
};


