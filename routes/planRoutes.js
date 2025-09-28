const express = require('express');
const planController = require('../controllers/planController');
const authController = require('../controllers/authController');

const router = express.Router();

router.use(authController.protect);

router.route('/active').get(planController.getActivePlan);

router
  .route('/')
  .get(planController.getAllPlans)
  .post(authController.restrictTo('admin'), planController.createPlan);

router.use(authController.restrictTo('admin'));

router
  .route('/:id')
  .get(planController.getPlanById)
  .patch(planController.updatePlanById)
  .delete(planController.deletePlanById);

module.exports = router;
