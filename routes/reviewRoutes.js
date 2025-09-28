const express = require('express');
const reviewController = require('../controllers/reviewController');
const authController = require('../controllers/authController');

const router = express.Router({ mergeParams: true });

// Public - get all reviews or property-specific reviews
router.get('/', reviewController.getAllReviews);

// Protect all routes
router.use(authController.protect);

router.get('/property/:propertyId', reviewController.getReviewsByProperty);

// Private (tenant only) - create, update, delete
router.post('/', authController.restrictTo('tenant'), reviewController.createReview);

router.route('/:id').get(reviewController.getReview);

router
  .route('/updateReview/:id')
  .patch(authController.restrictTo('tenant', 'admin'), reviewController.updateReview);

router
  .route('/deleteReview/:id')
  .delete(authController.restrictTo('tenant', 'admin'), reviewController.deleteReview);

module.exports = router;
