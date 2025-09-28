const qs = require('qs');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const APIFeatures = require('../utils/APIFeatures');
const Review = require('../models/Review');

exports.deleteOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.findByIdAndDelete(req.params.id);

    if (!doc) {
      return next(new AppError('No document found with that ID', 404));
    }

    res.status(204).json({
      status: 'success',
      data: null,
    });
  });

exports.updateOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!doc) {
      return next(new AppError('No document found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: {
        data: doc,
      },
    });
  });

exports.createOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.create(req.body);

    res.status(201).json({
      status: 'success',
      data: {
        data: doc,
      },
    });
  });

exports.getOne = (Model, populateOptions) =>
  catchAsync(async (req, res, next) => {
    let query = Model.findById(req.params.id);
    // const reviews = await Review.findById({ propertyId: req.params.id });
    // console.log(reviews);
    if (populateOptions) {
      if (Array.isArray(populateOptions)) {
        populateOptions.forEach((option) => {
          query = query.populate(option);
        });
      } else {
        query = query.populate(populateOptions);
      }
    }

    const doc = await query;

    if (!doc) {
      return next(new AppError('No document found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: {
        data: doc,
      },
    });
  });

// exports.getAll = (Model) =>
//   catchAsync(async (req, res, next) => {
//     let filter = {};

//     // Nested route support (like reviews on a specific property)
//     if (req.params.propertyId) filter = { propertyId: req.params.propertyId };

//     // ✅ Apply verified filter for tenants
//     if (req.user?.role === 'tenant') {
//       filter.isVerified = true;
//     }

//     const parsedQuery = qs.parse(req._parsedUrl.query);

//     const features = new APIFeatures(Model.find(filter), parsedQuery)
//       .filter()
//       .sort()
//       .limitFields()
//       .paginate();

//     const doc = await features.query;

//     res.status(200).json({
//       status: 'success',
//       results: doc.length,
//       data: {
//         data: doc,
//       },
//     });
//   });

exports.getAll = (Model) =>
  catchAsync(async (req, res, next) => {
    // To allow for nested GET reviews on a property, for example
    let filter = {};
    if (req.params.propertyId) filter = { propertyId: req.params.propertyId };

    // Use qs to deeply parse nested query parameters like rentAmount[gt]
    const parsedQuery = qs.parse(req._parsedUrl.query);

    const features = new APIFeatures(Model.find(filter), parsedQuery)
      .filter()
      .sort()
      .limitFields()
      .paginate();
    const doc = await features.query;

    // SEND RESPONSE
    res.status(200).json({
      status: 'success',
      results: doc.length,
      data: {
        data: doc,
      },
    });
  });
