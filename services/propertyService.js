const PropertyListing = require("../models/PropertyListing");
const AppError = require("../utils/appError");

exports.createProperty = async (propertyData) => {
  const newProperty = await PropertyListing.create(propertyData);
  return newProperty;
};

exports.getAllProperties = async (query) => {
  // Implement filtering, sorting, pagination here
  const properties = await PropertyListing.find(query);
  return properties;
};

exports.getPropertyById = async (id) => {
  const property = await PropertyListing.findById(id);
  if (!property) {
    throw new AppError("No property found with that ID", 404);
  }
  return property;
};

exports.updateProperty = async (id, updateData) => {
  const property = await PropertyListing.findByIdAndUpdate(id, updateData, {
    new: true,
    runValidators: true,
  });
  if (!property) {
    throw new AppError("No property found with that ID", 404);
  }
  return property;
};

exports.deleteProperty = async (id) => {
  const property = await PropertyListing.findByIdAndDelete(id);
  if (!property) {
    throw new AppError("No property found with that ID", 404);
  }
  return null;
};
