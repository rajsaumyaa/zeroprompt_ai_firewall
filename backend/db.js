const mongoose = require('mongoose');
const ScanLog  = require('./models/Log');

let isConnected = false;
const inMemoryLogs = [];

async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.log('ℹ [DB] MONGODB_URI not provided. Operating in memory-only mode.');
    return false;
  }

  if (isConnected) return true;

  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000
    });
    isConnected = true;
    console.log('✅ [DB] Connected to MongoDB Atlas successfully.');
    return true;
  } catch (err) {
    console.error('⚠ [DB] MongoDB Connection failed:', err.message);
    console.log('ℹ [DB] Falling back to memory-only log storage.');
    return false;
  }
}

async function saveLog(scanData, clientIp = '127.0.0.1') {
  const logEntry = {
    ...scanData,
    clientIp,
    createdAt: new Date()
  };

  if (isConnected) {
    try {
      await ScanLog.create(logEntry);
    } catch (err) {
      console.error('⚠ [DB] Failed to save log to MongoDB:', err.message);
      inMemoryLogs.unshift(logEntry);
    }
  } else {
    inMemoryLogs.unshift(logEntry);
    if (inMemoryLogs.length > 200) inMemoryLogs.pop(); // Keep last 200 in memory
  }
}

async function getLogs(limit = 50) {
  if (isConnected) {
    try {
      return await ScanLog.find().sort({ createdAt: -1 }).limit(limit).lean();
    } catch (err) {
      console.error('⚠ [DB] Failed to fetch logs from MongoDB:', err.message);
      return inMemoryLogs.slice(0, limit);
    }
  }
  return inMemoryLogs.slice(0, limit);
}

async function clearLogs() {
  if (isConnected) {
    try {
      await ScanLog.deleteMany({});
    } catch (err) {
      console.error('⚠ [DB] Failed to clear MongoDB logs:', err.message);
    }
  }
  inMemoryLogs.length = 0;
}

module.exports = {
  connectDB,
  saveLog,
  getLogs,
  clearLogs
};
