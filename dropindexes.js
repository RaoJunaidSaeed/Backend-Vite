const mongoose = require('mongoose');

async function dropOldIndex() {
  try {
    // Connect to DB (you can replace with your actual Mongo URI)
    await mongoose.connect('mongodb://127.0.0.1:27017/rentofix');

    const db = mongoose.connection.db;
    const collection = db.collection('reviews');

    const indexes = await collection.indexes();
    console.log('📌 Existing indexes:', indexes);

    const indexName = 'property_1_tenant_1'; // adjust if needed based on above log

    await collection.dropIndex(indexName);
    console.log(`✅ Dropped index: ${indexName}`);

    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error dropping index:', error);
    process.exit(1);
  }
}

dropOldIndex();
