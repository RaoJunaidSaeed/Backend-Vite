const express = require("express");
const paymentController = require("../controllers/paymentController");
const authController = require("../controllers/authController");

const router = express.Router();

router.use(authController.protect);

router.post("/create-payment-intent", paymentController.createPaymentIntent);

router.post("/record-payment/:planId", paymentController.createPayment);

router.use(authController.restrictTo("admin"));

router.route("/").get(paymentController.getAllPayment);

router
  .route("/:id")
  .get(paymentController.getPaymentById)
  .patch(paymentController.updatePaymentById)
  .delete(paymentController.deletePaymentById);

module.exports = router;
