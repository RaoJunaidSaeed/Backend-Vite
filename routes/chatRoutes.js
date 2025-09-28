const express = require('express');
const chatController = require('../controllers/chatController');
const authController = require('../controllers/authController'); // assuming you have JWT protect middleware

const router = express.Router();

// Protect all chat routes
router.use(authController.protect);

// Support chat
router.post('/support', chatController.getOrCreateSupportChat);

// Booking chat
router.post('/booking', chatController.getOrCreateBookingChat);

// Messages
router.post('/message', chatController.sendMessage);
router.get('/messages/:conversationId', chatController.getMessages);

router.get(
  '/admin/support',
  authController.restrictTo('admin'), // only admin can access
  chatController.getAllSupportConversations
);

module.exports = router;
