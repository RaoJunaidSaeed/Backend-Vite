const Booking = require("../models/Booking");
const AppError = require("../utils/appError");

exports.createBooking = async (bookingData) => {
  const newBooking = await Booking.create(bookingData);
  return newBooking;
};

exports.getAllBookings = async () => {
  const bookings = await Booking.find();
  return bookings;
};

exports.getBookingById = async (id) => {
  const booking = await Booking.findById(id);
  if (!booking) {
    throw new AppError("No booking found with that ID", 404);
  }
  return booking;
};

exports.updateBooking = async (id, updateData) => {
  const booking = await Booking.findByIdAndUpdate(id, updateData, {
    new: true,
    runValidators: true,
  });
  if (!booking) {
    throw new AppError("No booking found with that ID", 404);
  }
  return booking;
};

exports.deleteBooking = async (id) => {
  const booking = await Booking.findByIdAndDelete(id);
  if (!booking) {
    throw new AppError("No booking found with that ID", 404);
  }
  return null;
};

exports.approveBooking = async (bookingId, ownerId) => {
  const booking = await Booking.findOneAndUpdate(
    { _id: bookingId, ownerId: ownerId, status: "pending" },
    { status: "approved" },
    { new: true }
  );
  if (!booking) {
    throw new AppError("Booking not found or not pending for this owner", 404);
  }
  return booking;
};

exports.rejectBooking = async (bookingId, ownerId) => {
  const booking = await Booking.findOneAndUpdate(
    { _id: bookingId, ownerId: ownerId, status: "pending" },
    { status: "rejected" },
    { new: true }
  );
  if (!booking) {
    throw new AppError("Booking not found or not pending for this owner", 404);
  }
  return booking;
};


