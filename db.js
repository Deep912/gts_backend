const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  idleTimeoutMillis: 30000, // Disconnect idle connections after 30s
  connectionTimeoutMillis: 2000, // Timeout for new connections
});

pool.on("connect", () => console.log("Connected to PostgreSQL database."));
pool.on("error", (err) => console.error("Database connection error:", err));

module.exports = pool;
