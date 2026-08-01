const mongoose = require('mongoose');

const ScanLogSchema = new mongoose.Schema({
  prompt: { type: String, required: true },
  sanitized: { type: String },
  score: { type: Number, required: true },
  status: { type: String, required: true, enum: ['ALLOWED', 'SANITIZE', 'BLOCKED'] },
  findings: [{
    name: String,
    category: String,
    severity: String,
    score: Number,
    layer: String,
    match: String,
    deobfuscated: Boolean,
    sourceLabel: String
  }],
  contextFlags: [String],
  decodedLayers: [{
    method: String,
    decoded: String,
    confidence: Number
  }],
  threatMap: { type: Map, of: Number },
  clientIp: { type: String, default: '127.0.0.1' },
  createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 } // Auto-expire after 30 days
});

module.exports = mongoose.model('ScanLog', ScanLogSchema);
