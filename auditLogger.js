// auditLogger.js
const pool = require("./db"); // Adjust the path as needed

const logEvent = async (eventType, userId, details) => {
  try {
    await pool.query(
      "INSERT INTO audit_logs (event_type, user_id, details) VALUES ($1, $2, $3)",
      [eventType, userId, details]
    );
  } catch (error) {
    console.error("Failed to log event:", error);
  }
};

module.exports = { logEvent };
