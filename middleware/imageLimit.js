// middlewares/imageLimit.js
const checkImageLimit = (req, res, next) => {
  const files = req.files?.images || [];
  if (files.length > 5) {
    return res.status(400).json({
      status: "fail",
      message: "You can upload a maximum of 5 images only.",
    });
  }
  next();
};

module.exports = checkImageLimit;
