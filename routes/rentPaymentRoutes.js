const express = require('express');
const rentPaymentController = require('../controllers/rentPaymentController');
const authController = require('../controllers/authController');

const router = express.Router();

router.use(authController.protect);

// Tenant routes
router.post(
  '/create-payment-intent',
  authController.restrictTo('tenant'),
  rentPaymentController.createRentPaymentIntent
);
router.post(
  '/initiate',
  authController.restrictTo('tenant'),
  rentPaymentController.initiateRentPayment
);
router.get(
  '/my-payments',
  authController.restrictTo('tenant'),
  rentPaymentController.getTenantPaymentHistory
);

router.get(
  '/my-payments/:propertyId',
  authController.restrictTo('tenant'),
  rentPaymentController.getTenantPropertyPayment
);

router.get('/check/:propertyId/:tenantId', rentPaymentController.checkRentPaymentStatus);
// Owner routes
router.get(
  '/property/:propertyId',
  authController.restrictTo('owner'),
  rentPaymentController.getPropertyPaymentHistory
);

router.patch(
  '/verify/:paymentId',
  authController.restrictTo('owner'),
  rentPaymentController.verifyRentPayment
);
router.get(
  '/my-properties-payments',
  authController.restrictTo('owner'),
  rentPaymentController.getOwnerPaymentHistory
);

// Admin routes
router.use(authController.restrictTo('admin'));
router.route('/').get(rentPaymentController.getAllRentPayments);
router
  .route('/:id')
  .get(rentPaymentController.getRentPaymentById)
  .patch(rentPaymentController.updateRentPaymentById)
  .delete(rentPaymentController.deleteRentPaymentById);

module.exports = router;
