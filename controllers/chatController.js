const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const User = require('../models/User');
const PropertyListing = require('../models/PropertyListing');
const catchAsync = require('../utils/catchAsync');

// 🔹 Create/Get Support Chat
exports.getOrCreateSupportChat = catchAsync(async (req, res, next) => {
  const userId = req.user._id;
  const admin = await User.findOne({ role: 'admin' });

  if (!admin) {
    return res.status(404).json({ message: 'Admin not found' });
  }

  let conversation = await Conversation.findOne({
    members: { $all: [userId, admin._id] },
    type: 'support',
  });

  if (!conversation) {
    conversation = await Conversation.create({
      members: [userId, admin._id],
      type: 'support',
    });
  }

  // ✅ fetch existing messages for this conversation
  const messages = await Message.find({ conversationId: conversation._id }).sort('createdAt');

  res.status(200).json({
    status: 'success',
    conversation,
    messages,
  });
});

// 🔹 Create/Get Booking Chat
exports.getOrCreateBookingChat = catchAsync(async (req, res, next) => {
  const { propertyId, tenantId, ownerId } = req.body;

  const property = await PropertyListing.findById(propertyId);
  if (!property) {
    return res.status(404).json({ message: 'Property not found' });
  }

  let conversation = await Conversation.findOne({
    members: { $all: [tenantId, ownerId] },
    type: 'booking',
    propertyId,
  });

  if (!conversation) {
    conversation = await Conversation.create({
      members: [tenantId, ownerId],
      type: 'booking',
      propertyId,
    });
  }

  res.status(200).json({
    status: 'success',
    conversation,
  });
});

// 🔹 Send Message
exports.sendMessage = catchAsync(async (req, res, next) => {
  const { conversationId, content } = req.body;
  const senderId = req.user._id;

  if (!conversationId || !content) {
    return res.status(400).json({ message: 'conversationId and content required' });
  }

  const conversation = await Conversation.findById(conversationId);
  if (!conversation) {
    return res.status(404).json({ message: 'Conversation not found' });
  }
  const receiverId = conversation.members.find((id) => id.toString() !== req.user._id.toString());

  const message = await Message.create({
    conversationId,
    senderId,
    receiverId,
    content,
  });

  // update lastMessage field
  conversation.lastMessage = content;
  await conversation.save();

  // // Broadcast to all sockets in that conversation
  const io = req.app.get('io');
  io.to(conversationId).emit('messageReceived', message);

  // // emit to socket room if you have socket.io wired
  // if (req.io) {
  //   req.io.to(conversationId.toString()).emit('messageReceived', message);
  // }

  res.status(201).json({
    status: 'success',
    message,
  });
});

exports.getMessages = catchAsync(async (req, res, next) => {
  const { conversationId } = req.params;

  const messages = await Message.find({ conversationId }).sort({ createdAt: 1 }); // ✅ oldest → newest

  res.status(200).json({
    status: 'success',
    results: messages.length,
    messages,
  });
});

// 🔹 Get Messages with Pagination
// exports.getMessages = catchAsync(async (req, res, next) => {
//   const { conversationId } = req.params;
//   const { page = 1, limit = 20 } = req.query;

//   const messages = await Message.find({ conversationId })
//     .sort({ createdAt: 1 }) // ✅ oldest first
//     .skip((page - 1) * limit)
//     .limit(parseInt(limit));

//   res.status(200).json({
//     status: 'success',
//     results: messages.length,
//     messages,
//   });
// });

exports.getAllSupportConversations = catchAsync(async (req, res, next) => {
  const conversations = await Conversation.find({ type: 'support' }).populate(
    'members',
    'firstName lastName email'
  );

  res.status(200).json({
    status: 'success',
    conversations,
  });
});

// exports.getOrCreateSupportChat = catchAsync(async (req, res, next) => {
//   const userId = req.user._id; // tenant or owner
//   const admin = await User.findOne({ role: 'admin' });

//   if (!admin) {
//     return res.status(404).json({ message: 'Admin not found' });
//   }

//   let conversation = await Conversation.findOne({
//     members: { $all: [userId, admin._id] },
//     type: 'support',
//   });

//   if (!conversation) {
//     conversation = await Conversation.create({
//       members: [userId, admin._id],
//       type: 'support',
//     });
//   }

//   res.status(200).json({
//     status: 'success',
//     conversation,
//   });
// });

// exports.sendMessage = catchAsync(async (req, res, next) => {
//   const { conversationId, content, receiverId } = req.body;
//   const senderId = req.user._id;

//   const conversation = await Conversation.findById(conversationId);
//   if (!conversation) {
//     return res.status(404).json({ message: 'Conversation not found' });
//   }

//   const message = await Message.create({
//     conversationId,
//     senderId,
//     receiverId,
//     content,
//   });

//   // Update conversation lastMessage
//   conversation.lastMessage = content;
//   await conversation.save();

//   res.status(201).json({
//     status: 'success',
//     message,
//   });
// });
