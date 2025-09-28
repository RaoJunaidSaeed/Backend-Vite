// models/Conversation.js
const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema(
  {
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    type: { type: String, enum: ['booking', 'support'], required: true },
    propertyId: { type: mongoose.Schema.Types.ObjectId, ref: 'PropertyListing', default: null },
    lastMessage: { type: String },
  },
  { timestamps: true }
);

// Virtual populate for messages
conversationSchema.virtual('messages', {
  ref: 'Message',
  foreignField: 'conversationId',
  localField: '_id',
});

module.exports = mongoose.model('Conversation', conversationSchema);
