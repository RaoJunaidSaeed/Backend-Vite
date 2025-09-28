const AppError = require('../utils/appError');

const handleCastErrorDb = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  const field = err?.keyValue ? Object.keys(err.keyValue)[0] : 'unknown';
  const value = err?.keyValue?.[field] || 'unknown';
  let message;

  if (field === 'bookingId') {
    message = `You have already submitted a review for this booking.`;
  } else {
    message = `Duplicate value for field "${field}": ${value}. Please use another value!`;
  }

  return new AppError(message, 400);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map((el) => el.message);

  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};
const handleJWTError = () => {
  return new AppError('Invalid Token. Please login again!', 401);
};
const handleJWTExpireError = () => {
  return new AppError('Token Expired. Login again to access to data!', 401);
};

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
    error: err,
    stack: err.stack,
  });
};

const sendErrorPro = (err, res) => {
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  } else {
    res.status(500).json({
      status: 'Error',
      // message: "Something went very wrong 💥",
      message: err.message,
    });
  }
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'Error';
  if (process.env.NODE_ENV === 'development') {
    console.log('This is development');

    sendErrorDev(err, res);
  } else if (process.env.NODE_ENV === 'production') {
    console.log('This is production');
    let error = err;
    if (error.name === 'CastError') error = handleCastErrorDb(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpireError();

    sendErrorPro(error, res);
  }
};
