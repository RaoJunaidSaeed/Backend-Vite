class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.isOperational = true;
    // console.log('hello from constructor');
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith("4") ? "Fail" : "Error";

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
