const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');
const upload = require('../utils/upload');

const router = express.Router();

router.use(authController.protect);

router.get('/getme', authController.getMe, userController.getUser);
router.patch(
  '/updateMe',
  upload.single('photo'), // Handle photo upload
  userController.updateMe
);
router.delete('/deleteMe', userController.deleteMe);

router.use(authController.restrictTo('admin'));

router.route('/').get(userController.getAllUsers).post(userController.createUser);

router
  .route('/:id')
  .get(userController.getUser)
  .patch(upload.single('photo'), userController.updateUser) // ✅ fix applied
  .delete(userController.deleteUser);

module.exports = router;
