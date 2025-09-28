const express = require('express');
const propertyController = require('../controllers/propertyController');
const authController = require('../controllers/authController');
const reviewRouter = require('./reviewRoutes');
const upload = require('../utils/upload');

const router = express.Router();

// Nested route: redirect to review routes if matched
router.use('/:propertyId/createReview', reviewRouter);

router
  .route('/')
  .get(propertyController.getAllProperties)
  .post(
    authController.protect,
    authController.restrictTo('owner', 'admin'),
    upload.array('images', 5),
    propertyController.createProperty
  );

router
  .route('/my-properties')
  .get(
    authController.protect,
    authController.restrictTo('owner', 'admin'),
    propertyController.getOwnerProperties
  );

router
  .route('/:id')
  .get(propertyController.getOneProperty)
  .patch(
    authController.protect,
    authController.restrictTo('owner', 'admin'),
    upload.array('images', 5),
    propertyController.updateProperty
  )
  .delete(
    authController.protect,
    authController.restrictTo('owner', 'admin'),
    propertyController.deleteProperty
  );

router
  .route('/verify/:id')
  .patch(
    authController.protect,
    authController.restrictTo('admin'),
    propertyController.verifyProperty
  );

module.exports = router;
