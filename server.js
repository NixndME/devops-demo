const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static('public'));

// API endpoint for demo
app.get('/api/status', (req, res) => {
  res.json({
    message: "DevOps Demo is Live! 🚀",
    timestamp: new Date().toISOString(),
    version: process.env.APP_VERSION || "1.0.0",
    environment: process.env.NODE_ENV || "development"
  });
});

// Health check for Kubernetes
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', uptime: process.uptime() });
});

app.listen(PORT, () => {
  console.log(`🚀 DevOps Demo App running on port ${PORT}`);
  console.log(`📝 Open http://localhost:${PORT} to view`);
});