const express = require('express');
const bookingController = require('../controllers/bookingController');
const authController = require('../controllers/authController');

const router = express.Router();

router.use(authController.protect);

router.route('/').get(authController.restrictTo('admin'), bookingController.getAllBookings);

// ⬇️ Updated POST route to include :propertyId in the URL
router
  .route('/createBooking/:propertyId')
  .post(
    authController.protect,
    authController.restrictTo('tenant'),
    bookingController.createBooking
  );

// Protect this route so only logged-in tenants can access
router.get('/my-bookings', authController.protect, bookingController.getMyBookingsOrRequests);

router
  .route('/:id')
  .get(bookingController.getBooking)
  .patch(bookingController.updateBooking)
  .delete(bookingController.deleteBooking);

router.get(
  '/myBooking/:propertyId',
  authController.restrictTo('tenant'),
  bookingController.getMyBookingForProperty
);
router
  .route('/approveBooking/:id')
  .patch(authController.restrictTo('owner'), bookingController.approveBooking);

router
  .route('/rejectBooking/:id')
  .patch(authController.restrictTo('owner'), bookingController.rejectBooking);

router.patch(
  '/update-status/:id',
  authController.restrictTo('owner'),
  bookingController.updateBookingStatus
);

module.exports = router;
