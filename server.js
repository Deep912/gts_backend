require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");
const { authenticateJWT } = require("./middleware/authMiddleware");
const { logEvent } = require("./auditLogger");
const app = express();

// ✅ Middleware: Ensure Express Can Parse JSON & URL-encoded Data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ CORS Policy: Allow Vercel, ngrok, and localhost
const allowedOrigins = [
  "https://fr-gts-demo-1bvh.vercel.app", // Vercel Frontend
  "http://localhost:5173", // Local Frontend for Testing
  "http://127.0.0.1:5173", // Alternative Local Frontend
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (
        !origin ||
        allowedOrigins.includes(origin) ||
        origin.includes("ngrok")
      ) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "ngrok-skip-browser-warning",
    ],
  })
);

// ✅ Handle Preflight OPTIONS Requests
app.options("*", cors());

app.set("trust proxy", true);

// ✅ Root Test Route
app.get("/", (req, res) => {
  res.json({ message: "Server is running and fully connected!" });
});

// ✅ Debug Route for JSON Parsing
app.post("/test-json", (req, res) => {
  console.log("📩 Received JSON:", req.body);
  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({ error: "Invalid JSON data received" });
  }
  res.json({ message: "JSON received successfully", data: req.body });
});

// ✅ USER AUTHENTICATION (Login)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const userAgent = req.headers["user-agent"] || "Unknown device";
  console.log("Client IP:", req.ip, "User Agent:", userAgent);

  if (!username || !password) {
    // Log the failed attempt without a user ID, including the IP address and user agent
    await logEvent(
      "login_failed",
      null,
      { username, reason: "Missing credentials" },
      req.ip,
      userAgent
    );
    console.log("Logged event: login_failed (Missing credentials)");
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    const userResult = await pool.query(
      "SELECT id, username, password, role FROM users WHERE username = $1",
      [username]
    );

    if (userResult.rows.length === 0) {
      // Log login failed with reason "User not found", including the IP address and user agent
      await logEvent(
        "login_failed",
        null,
        { username, reason: "User not found" },
        req.ip,
        userAgent
      );
      console.log("Logged event: login_failed (User not found)");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = userResult.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      // Log login failed with incorrect password, including the IP address and user agent
      await logEvent(
        "login_failed",
        user.id,
        { username, reason: "Incorrect password" },
        req.ip,
        userAgent
      );
      console.log("Logged event: login_failed (Incorrect password)");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Log successful login, including the IP address and user agent
    const logEvent = async (
      eventType,
      userId,
      details,
      ipAddress = null,
      userAgent = null,
      targetId = null,
      targetType = null
    ) => {
      try {
        await pool.query(
          `INSERT INTO audit_logs 
            (event_type, user_id, details, ip_address, user_agent, target_id, target_type)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            eventType,
            userId,
            details,
            ipAddress,
            userAgent,
            targetId,
            targetType,
          ]
        );
      } catch (error) {
        console.error("Failed to log event:", error);
      }
    };

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// ✅ Worker Stats API
app.get("/worker-stats", authenticateJWT, async (req, res) => {
  try {
    const stats = await pool.query(
      `SELECT 
        COUNT(CASE WHEN action = 'dispatch' THEN 1 END) AS dispatched,
        COUNT(CASE WHEN action = 'receive_empty' OR action = 'receive_filled' THEN 1 END) AS received,
        COUNT(CASE WHEN action = 'refill' THEN 1 END) AS refilled
       FROM transactions WHERE user_id = $1`,
      [req.user.id]
    );

    res.json(stats.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// ✅ Recent Transactions API
app.get("/worker-transactions", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT serial_number, action, timestamp FROM transactions WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 10",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/worker/transactions", authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const search = req.query.search || "";
    const limit = parseInt(req.query.limit) || 10;
    const offset = parseInt(req.query.offset) || 0;

    // Build the base query including allowed actions and using performed_by column
    let baseQuery = `
      FROM transactions t
      LEFT JOIN companies c ON t.company_id = c.id
      WHERE t.user_id = $1
        AND LOWER(t.action) IN ('dispatch', 'receive_empty', 'receive_filled')
    `;
    const queryParams = [userId];

    if (search) {
      baseQuery += " AND ('TXN-' || t.id) ILIKE $2";
      queryParams.push(`%${search}%`);
    }

    // Count total matching records for pagination
    const countQuery = `SELECT COUNT(*) ${baseQuery}`;
    const countResult = await pool.query(countQuery, queryParams);
    const total = parseInt(countResult.rows[0].count);

    // Fetch the actual rows using limit and offset, ordered by t.id DESC
    let dataQuery = `
      SELECT 
        ('TXN-' || t.id) AS transaction_number,
        t.chalan_number,
        t.action,
        t.cylinder_id,
        c.name AS company_name,
        t.performed_by,
        t.timestamp
      ${baseQuery}
      ORDER BY t.id DESC
      LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}
    `;
    queryParams.push(limit, offset);

    const result = await pool.query(dataQuery, queryParams);

    res.json({ total, rows: result.rows });
  } catch (error) {
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/dispatch-cylinder", authenticateJWT, async (req, res) => {
  const { serialNumbers, companyId, gas_product_id, quantity } = req.body;

  console.log("Received Dispatch Data:", req.body);

  if (!Array.isArray(serialNumbers) || serialNumbers.length === 0) {
    return res
      .status(400)
      .json({ error: "Invalid request. Provide an array of serial numbers." });
  }
  if (!companyId || !gas_product_id || !quantity) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  try {
    // Check if the company exists
    const checkCompany = await pool.query(
      "SELECT id FROM companies WHERE id = $1",
      [companyId]
    );
    if (checkCompany.rows.length === 0) {
      return res.status(400).json({ error: "Invalid company ID" });
    }

    // Check if serial numbers exist in the database
    const checkCylinders = await pool.query(
      "SELECT serial_number FROM cylinders WHERE serial_number = ANY($1::text[])",
      [serialNumbers]
    );
    if (checkCylinders.rows.length !== serialNumbers.length) {
      return res.status(400).json({
        error: "Some cylinders are not found in the database",
        found: checkCylinders.rows.map((row) => row.serial_number),
        missing: serialNumbers.filter(
          (sn) => !checkCylinders.rows.some((row) => row.serial_number === sn)
        ),
      });
    }

    // Update cylinders: set status to 'dispatched' and assign the company ID.
    await pool.query(
      `UPDATE cylinders 
       SET status = 'dispatched', company_id = $1 
       WHERE serial_number = ANY($2::text[])`,
      [companyId, serialNumbers]
    );

    // Generate a chalan number using the last 4 digits of the timestamp and a random two-digit number.
    const timestampStr = Date.now().toString();
    const randomPart = Math.floor(10 + Math.random() * 90); // Random number between 10 and 99
    const chalanNumber = `CL-${timestampStr.slice(-4)}${randomPart}`;

    // Log the dispatch transaction and return the auto-generated id.
    const insertResult = await pool.query(
      `INSERT INTO transactions (user_id, cylinder_id, action, company_id, chalan_number, performed_by)
       SELECT $1, id, 'dispatch', $2, $4, $5
       FROM cylinders
       WHERE serial_number = ANY($3::text[])
       RETURNING id`,
      [req.user.id, companyId, serialNumbers, chalanNumber, req.user.username]
    );

    // Use the returned id as the transaction identifier.
    const transactionId = `TXN-${insertResult.rows[0].id}`;

    // Query the product price from the gas_products table.
    const productRes = await pool.query(
      "SELECT price FROM gas_products WHERE id = $1",
      [gas_product_id]
    );
    if (productRes.rows.length === 0) {
      return res.status(400).json({ error: "Invalid gas product." });
    }
    const price = parseFloat(productRes.rows[0].price);
    const totalAmount = price * Number(quantity);

    res.json({
      message: "Cylinders dispatched successfully!",
      transactionId,
      chalanNumber,
      price,
      totalAmount,
    });
  } catch (error) {
    console.error("Dispatch Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/products", authenticateJWT, async (req, res) => {
  try {
    const query = `
      SELECT 
        gp.id,  
        gp.gas_sub_type_id,
        gp.capacity,
        gp.measurement_unit,
        gp.description,
        gp.created_at,
        gp.price,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS label
      FROM gas_products gp
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      ORDER BY gp.created_at DESC;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/companies", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM companies ORDER BY name");
    res.json(result.rows);
  } catch (error) {
    console.error("Company Fetch Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// ====================================
// 🔹 SYSTEM UTILITIES
// ====================================
app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      message: "Database connection successful!",
      server_time: result.rows[0].now,
    });
  } catch (error) {
    console.error("Database Connection Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/available-cylinders", authenticateJWT, async (req, res) => {
  const { gas_product_id } = req.query;

  if (!gas_product_id) {
    return res.status(400).json({ error: "Gas product id is required" });
  }

  try {
    const query = `
      SELECT c.serial_number, gt.name AS gas_type, c.manufacture_date
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      WHERE c.status = 'available' AND gp.id = $1
    `;
    const result = await pool.query(query, [gas_product_id]);
    res.json(result.rows);
  } catch (error) {
    console.error("Available Cylinders Fetch Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/dispatched-cylinders", authenticateJWT, async (req, res) => {
  const { companyId } = req.query;
  if (!companyId) {
    return res.status(400).json({ error: "Company ID is required" });
  }
  try {
    const result = await pool.query(
      `
      SELECT 
        c.serial_number,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS product_label
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      WHERE c.company_id = $1 AND c.status = 'dispatched'
      `,
      [Number(companyId)]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching dispatched cylinders:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Receive Cylinders API

app.post("/receive-cylinder", authenticateJWT, async (req, res) => {
  const { emptySerialNumbers, filledSerialNumbers, companyId } = req.body;

  // Validate input: at least one list must be non-empty
  if (
    (!Array.isArray(emptySerialNumbers) || emptySerialNumbers.length === 0) &&
    (!Array.isArray(filledSerialNumbers) || filledSerialNumbers.length === 0)
  ) {
    return res.status(400).json({ error: "Provide at least one cylinder ID." });
  }

  try {
    // Update empty cylinders: mark status as 'empty' and reset company_id
    if (emptySerialNumbers && emptySerialNumbers.length > 0) {
      await pool.query(
        "UPDATE cylinders SET status = 'empty', company_id = NULL WHERE serial_number = ANY($1::text[])",
        [emptySerialNumbers]
      );
    }

    // Update filled cylinders: mark status as 'available' and reset company_id
    if (filledSerialNumbers && filledSerialNumbers.length > 0) {
      await pool.query(
        "UPDATE cylinders SET status = 'available', company_id = NULL WHERE serial_number = ANY($1::text[])",
        [filledSerialNumbers]
      );
    }

    // Combine all serial numbers into one array
    const allSerialNumbers = [
      ...(emptySerialNumbers || []),
      ...(filledSerialNumbers || []),
    ];

    // Generate a chalan number using the dispatch style ("CL-" prefix)
    const timestampStr = Date.now().toString();
    const randomPart = Math.floor(10 + Math.random() * 90); // random between 10 and 99
    const receiveChalanNumber = `CL-${timestampStr.slice(-4)}${randomPart}`;

    // Insert transaction records for all received cylinders using a single query.
    // The action is determined by the updated status in the cylinders table.
    const insertResult = await pool.query(
      `INSERT INTO transactions (user_id, cylinder_id, action, company_id, chalan_number, performed_by)
       SELECT $1, id,
         CASE 
           WHEN status = 'empty' THEN 'receive_empty'
           WHEN status = 'available' THEN 'receive_filled'
           ELSE 'receive'
         END,
         $2, $3, $4
       FROM cylinders
       WHERE serial_number = ANY($5::text[])
       RETURNING id`,
      [
        req.user.id,
        companyId,
        receiveChalanNumber,
        req.user.username,
        allSerialNumbers,
      ]
    );

    // Use the returned id to create a transaction ID (like in your dispatch endpoint)
    const transactionId = `TXN-${insertResult.rows[0].id}`;

    // Fetch detailed cylinder info including a computed product label.
    // The product label is computed by joining gas_products, gas_sub_types, and gas_types.
    const cylinderDetailsResult = await pool.query(
      `SELECT 
         c.serial_number, 
         c.gas_product_id, 
         CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity::text, ' ', gp.measurement_unit) AS productlabel
       FROM cylinders c
       JOIN gas_products gp ON c.gas_product_id = gp.id
       JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
       JOIN gas_types gt ON gst.gas_type_id = gt.id
       WHERE c.serial_number = ANY($1::text[])`,
      [allSerialNumbers]
    );

    const receivedCylinders = cylinderDetailsResult.rows.map((row) => ({
      serial_number: row.serial_number,
      gas_product_id: row.gas_product_id,
      productLabel: row.productlabel, // computed value from our query
    }));

    res.json({
      message: "Cylinders received successfully!",
      transactionId,
      chalanNumber: receiveChalanNumber,
      receivedCylinders,
    });
  } catch (error) {
    console.error("Receive Cylinder Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/refill-cylinder", authenticateJWT, async (req, res) => {
  const { cylinderIds } = req.body;

  if (!Array.isArray(cylinderIds) || cylinderIds.length === 0) {
    return res.status(400).json({ error: "Provide an array of cylinder IDs." });
  }

  try {
    // Ensure all cylinders are EMPTY before refilling
    const checkStatus = await pool.query(
      "SELECT serial_number FROM cylinders WHERE serial_number = ANY($1::text[]) AND status != 'empty'",
      [cylinderIds]
    );

    if (checkStatus.rows.length > 0) {
      return res.status(400).json({
        error: `Cylinders ${checkStatus.rows
          .map((c) => c.serial_number)
          .join(", ")} are not empty and cannot be refilled.`,
      });
    }

    // Update status to 'refilling'
    await pool.query(
      "UPDATE cylinders SET status = 'refilling' WHERE serial_number = ANY($1::text[])",
      [cylinderIds]
    );

    // Log the transaction
    await pool.query(
      `INSERT INTO transactions (user_id, cylinder_id, action) 
       SELECT $1, id, 'refill' FROM cylinders WHERE serial_number = ANY($2::text[])`,
      [req.user.id, cylinderIds]
    );

    res.json({ message: "Cylinders sent for refilling!" });
  } catch (error) {
    console.error("Refill Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/refilling-cylinders", authenticateJWT, async (req, res) => {
  try {
    const query = `
      SELECT 
        c.serial_number,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS product_label,
        c.manufacture_date,
        c.status
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      WHERE c.status = 'refilling'
      ORDER BY c.serial_number;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching refilling cylinders:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/complete-refill", authenticateJWT, async (req, res) => {
  const { cylinderIds } = req.body;

  if (!Array.isArray(cylinderIds) || cylinderIds.length === 0) {
    return res.status(400).json({ error: "Provide an array of cylinder IDs." });
  }

  try {
    // Ensure all cylinders are in refilling status before updating
    const checkStatus = await pool.query(
      "SELECT serial_number FROM cylinders WHERE serial_number = ANY($1::text[]) AND status != 'refilling'",
      [cylinderIds]
    );

    if (checkStatus.rows.length > 0) {
      return res.status(400).json({
        error: `Cylinders ${checkStatus.rows
          .map((c) => c.serial_number)
          .join(", ")} are not in refilling status.`,
      });
    }

    // Update cylinders: set status to 'available' and increment cylinder_run_count by 1.
    const updateQuery = `
      UPDATE cylinders 
      SET status = 'available', 
          cylinder_run_count = COALESCE(cylinder_run_count, 0) + 1
      WHERE serial_number = ANY($1::text[])
      RETURNING serial_number, cylinder_run_count
    `;
    const updateResult = await pool.query(updateQuery, [cylinderIds]);

    res.json({
      message: "Cylinders marked as filled successfully!",
      updatedCylinders: updateResult.rows,
    });
  } catch (error) {
    console.error("Complete Refill Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/empty-cylinders", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT serial_number, gas_type, size FROM cylinders WHERE status = 'empty'"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Fetch Empty Cylinders Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/empty-cylinders-grouped", authenticateJWT, async (req, res) => {
  try {
    const query = `
      SELECT 
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS product_label,
        json_agg(
          json_build_object(
            'serial_number', c.serial_number,
            'manufacture_date', c.manufacture_date
          )
        ) AS cylinders
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      WHERE c.status = 'empty'
      GROUP BY product_label
      ORDER BY product_label;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Fetch Empty Cylinders Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

//admin
//part

app.get("/admin/gas-types", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name FROM gas_types ORDER BY name"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching gas types:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get(
  "/admin/gas-sub-types/:gasTypeId",
  authenticateJWT,
  async (req, res) => {
    const { gasTypeId } = req.params;

    try {
      const result = await pool.query(
        "SELECT id, name FROM gas_sub_types WHERE gas_type_id = $1 ORDER BY name",
        [gasTypeId]
      );
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching gas sub-types:", error);
      res.status(500).json({ error: "Database error", details: error.message });
    }
  }
);

app.get("/admin/transactions", authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== "admin" && req.user.role !== "owner") {
      return res.status(403).json({ error: "Access denied" });
    }

    const query = `
      SELECT t.action, c.name AS company_name, cyl.serial_number
      FROM transactions t
      LEFT JOIN companies c ON t.company_id = c.id
      LEFT JOIN cylinders cyl ON t.cylinder_id = cyl.id
      ORDER BY t.id DESC
      LIMIT 10;
    `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Admin Transactions Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/stats", authenticateJWT, async (req, res) => {
  try {
    console.log("🔹 Fetching admin stats...");

    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM cylinders) AS total_cylinders,
        (SELECT COUNT(*) FROM cylinders WHERE status = 'available') AS inventory_cylinders,
        (SELECT COUNT(*) FROM cylinders WHERE status = 'dispatched') AS total_dispatched,
        (SELECT COUNT(*) FROM cylinders WHERE status = 'refilled') AS total_refilled,
        (SELECT COUNT(*) FROM cylinders WHERE status = 'refilling') AS refilling_cylinders
    `);

    console.log("✅ Stats fetched:", stats.rows[0]);
    res.json(stats.rows[0]);
  } catch (error) {
    console.error("❌ Error fetching stats:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/trends", authenticateJWT, async (req, res) => {
  try {
    const trends = await pool.query(`
      SELECT 
        DATE(timestamp) AS date,
        COUNT(CASE WHEN action = 'refill' THEN 1 END) AS refilled,
        COUNT(CASE WHEN action = 'dispatch' THEN 1 END) AS dispatched
      FROM transactions
      WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
      GROUP BY date
      ORDER BY date ASC
    `);

    res.json(trends.rows);
  } catch (error) {
    console.error("❌ Error fetching trends:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/top-companies", authenticateJWT, async (req, res) => {
  try {
    const companies = await pool.query(`
      SELECT c.name AS company_name, COUNT(t.id) AS total_transactions
      FROM transactions t
      JOIN companies c ON t.company_id = c.id
      GROUP BY c.name
      ORDER BY total_transactions DESC
      LIMIT 5;
    `);

    res.json(companies.rows);
  } catch (error) {
    console.error("❌ Error fetching top companies:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/cylinders", authenticateJWT, async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  const offset = parseInt(req.query.offset) || 0;
  const search = req.query.search || "";
  try {
    let query = "SELECT * FROM cylinders";
    const params = [];
    if (search) {
      query += " WHERE serial_number ILIKE $1";
      params.push(`%${search}%`);
    }
    query +=
      " ORDER BY id DESC LIMIT $" +
      (params.length + 1) +
      " OFFSET $" +
      (params.length + 2);
    params.push(limit, offset);
    const result = await pool.query(query, params);

    // Count using the same search filter
    const countQuery =
      "SELECT COUNT(*) FROM cylinders" +
      (search ? " WHERE serial_number ILIKE $1" : "");
    const countParams = search ? [`%${search}%`] : [];
    const countResult = await pool.query(countQuery, countParams);

    res.json({
      total: parseInt(countResult.rows[0].count, 10),
      rows: result.rows,
    });
  } catch (error) {
    console.error("Error fetching cylinders:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/deleted-cylinders", authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== "admin" && req.user.role !== "owner") {
      return res.status(403).json({ error: "Access denied" });
    }

    const query = `
      SELECT d.serial_number, d.gas_type, d.size, d.deleted_by, u.username AS deleted_by_user, d.deleted_at
      FROM deleted_cylinders d
      JOIN users u ON d.deleted_by = u.id
      ORDER BY d.deleted_at DESC
    `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching deleted cylinders:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/admin/delete-cylinder", authenticateJWT, async (req, res) => {
  const { serial_number } = req.body;

  if (!serial_number) {
    return res
      .status(400)
      .json({ error: "Cylinder serial number is required." });
  }

  try {
    // 🔹 1️⃣ Check if cylinder exists
    const cylinderCheck = await pool.query(
      "SELECT * FROM cylinders WHERE serial_number = $1",
      [serial_number]
    );

    if (cylinderCheck.rows.length === 0) {
      return res.status(404).json({ error: "Cylinder not found." });
    }

    const cylinder = cylinderCheck.rows[0];

    // 🔹 2️⃣ Move cylinder to deleted_cylinders table (INCLUDING `status`)
    await pool.query(
      `INSERT INTO deleted_cylinders (serial_number, gas_type, size, status, deleted_by)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        cylinder.serial_number,
        cylinder.gas_type,
        cylinder.size,
        cylinder.status,
        req.user.id,
      ]
    );

    // 🔹 3️⃣ Delete from cylinders table
    await pool.query("DELETE FROM cylinders WHERE serial_number = $1", [
      serial_number,
    ]);

    await logEvent("delete_cylinder", req.user.id, {
      serial_number: cylinder.serial_number,
      size: cylinder.size,
      gas_type: cylinder.gas_type,
    });

    res.json({ message: "Cylinder deleted successfully and logged." });
  } catch (error) {
    console.error("Delete Cylinder Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Update a gas product
app.put("/admin/update-product/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const { gas_sub_type_id, capacity, measurement_unit, description, price } =
    req.body;

  if (
    !gas_sub_type_id ||
    !capacity ||
    !measurement_unit ||
    price === undefined
  ) {
    return res.status(400).json({
      error:
        "Missing required fields: gas_sub_type_id, capacity, measurement_unit, price",
    });
  }

  try {
    // Retrieve the gas sub type name for computing the product name.
    const gasSubTypeResult = await pool.query(
      "SELECT name FROM gas_sub_types WHERE id = $1",
      [gas_sub_type_id]
    );
    if (gasSubTypeResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid gas_sub_type_id" });
    }

    const gasSubTypeName = gasSubTypeResult.rows[0].name;
    // Compute the product name (e.g., "Industrial 50L")
    const computedName = `${gasSubTypeName} ${capacity}${measurement_unit}`;

    const result = await pool.query(
      `UPDATE gas_products 
       SET gas_sub_type_id = $1, capacity = $2, measurement_unit = $3, description = $4, price = $5, name = $6
       WHERE id = $7 RETURNING *`,
      [
        gas_sub_type_id,
        capacity,
        measurement_unit,
        description || "",
        price,
        computedName,
        id,
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({
      message: "Product updated successfully",
      gas_product: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Inventory Summary Endpoint
app.get("/admin/inventory-summary", authenticateJWT, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const offset = parseInt(req.query.offset) || 0;

    // Data query with pagination.
    const dataQuery = `
      SELECT 
        gp.id,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS product_name,
        COUNT(c.id) FILTER (WHERE c.status = 'available') AS available_count,
        COUNT(c.id) FILTER (WHERE c.status = 'dispatched') AS dispatched_count,
        COUNT(c.id) AS total_count
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      GROUP BY gp.id, product_name
      ORDER BY product_name
      LIMIT $1 OFFSET $2;
    `;

    // Count query for total number of grouped products.
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM (
        SELECT gp.id
        FROM cylinders c
        JOIN gas_products gp ON c.gas_product_id = gp.id
        JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
        JOIN gas_types gt ON gst.gas_type_id = gt.id
        GROUP BY gp.id
      ) AS sub;
    `;

    const dataResult = await pool.query(dataQuery, [limit, offset]);
    const countResult = await pool.query(countQuery);
    const total = parseInt(countResult.rows[0].total, 10);

    res.json({ total, rows: dataResult.rows });
  } catch (error) {
    console.error("Inventory Summary Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Delete a gas product
app.delete("/admin/delete-product/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "DELETE FROM gas_products WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json({
      message: "Product deleted successfully",
      gas_product: result.rows[0],
    });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/admin/update-cylinder-status", authenticateJWT, async (req, res) => {
  const { serial_number, status } = req.body;
  await pool.query(
    "UPDATE cylinders SET status = $1 WHERE serial_number = $2",
    [status, serial_number]
  );
  res.json({ message: "Status updated successfully!" });
});
app.post("/admin/add-cylinder", authenticateJWT, async (req, res) => {
  // Destructure the new required fields from the request body.
  // Note: We no longer need gas_type_id, gas_sub_type_id, size, product_grade, capacity, or measurement_unit.
  // Instead, we require a gas_product_id (which contains all that info) and manufacture_date.
  const {
    serial_number,
    gas_product_id,
    manufacture_date,
    status,
    company_id,
  } = req.body;

  // Validate required fields.
  if (!serial_number || !gas_product_id || !manufacture_date || !status) {
    return res.status(400).json({
      error:
        "Missing required fields: serial_number, gas_product_id, manufacture_date, status",
    });
  }

  try {
    // Insert into the updated cylinders table.
    // The table now references gas_product_id and stores manufacture_date instead of the individual gas details.
    await pool.query(
      `INSERT INTO cylinders 
       (serial_number, gas_product_id, manufacture_date, status, company_id, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
      [
        serial_number,
        gas_product_id,
        manufacture_date,
        status,
        company_id || null, // Allow NULL if no company is assigned initially.
      ]
    );

    // Log the event with the new cylinder details.
    await logEvent("add_cylinder", req.user.id, {
      serial_number,
      gas_product_id,
      manufacture_date,
      status,
      company_id,
    });

    res.json({ message: "Cylinder added successfully!" });
  } catch (error) {
    console.error("Database Insert Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/generate-cylinder-id", authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== "admin" && req.user.role !== "owner") {
      return res.status(403).json({ error: "Access denied" });
    }

    // 🔹 Get the highest cylinder ID from BOTH `cylinders` and `deleted_cylinders`
    const query = `
      SELECT serial_number FROM (
        SELECT serial_number FROM cylinders 
        WHERE serial_number ~ '^CYL[0-9]+$'
        UNION ALL
        SELECT serial_number FROM deleted_cylinders
        WHERE serial_number ~ '^CYL[0-9]+$'
      ) AS combined
      ORDER BY CAST(SUBSTRING(serial_number FROM 4) AS INTEGER) DESC 
      LIMIT 1;
    `;

    const result = await pool.query(query);

    let newId = "CYL1001"; // Default starting ID if no cylinders exist

    if (result.rows.length > 0) {
      const lastId = result.rows[0].serial_number;
      const lastNumber = parseInt(lastId.replace("CYL", ""), 10);
      newId = `CYL${lastNumber + 1}`;
    }

    res.json({ new_id: newId });
  } catch (error) {
    console.error("Error generating cylinder ID:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/admin/restore-cylinder", authenticateJWT, async (req, res) => {
  const { serial_number } = req.body;

  if (!serial_number) {
    return res
      .status(400)
      .json({ error: "Cylinder serial number is required." });
  }

  try {
    // 🔹 1️⃣ Check if the cylinder exists in `deleted_cylinders`
    const cylinderCheck = await pool.query(
      "SELECT * FROM deleted_cylinders WHERE serial_number = $1",
      [serial_number]
    );

    if (cylinderCheck.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Cylinder not found in deleted records." });
    }

    const cylinder = cylinderCheck.rows[0];

    // 🔹 2️⃣ Move the cylinder back to `cylinders`
    await pool.query(
      `INSERT INTO cylinders (serial_number, gas_type, size, status)
       VALUES ($1, $2, $3, $4)`,
      [
        cylinder.serial_number,
        cylinder.gas_type,
        cylinder.size,
        cylinder.status,
      ]
    );

    // 🔹 3️⃣ Remove the cylinder from `deleted_cylinders`
    await pool.query("DELETE FROM deleted_cylinders WHERE serial_number = $1", [
      serial_number,
    ]);

    // 1️⃣ Log the event
    await logEvent("restore_cylinder", req.user.id, {
      serial_number: cylinder.serial_number,
      size: cylinder.size,
      gas_type: cylinder.gas_type,
    });

    res.json({ message: "Cylinder restored successfully." });
  } catch (error) {
    console.error("Restore Cylinder Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/admin/update-cylinder-status", authenticateJWT, async (req, res) => {
  const { serial_number, status } = req.body;

  if (!serial_number || !status) {
    return res
      .status(400)
      .json({ error: "Cylinder serial number and status are required." });
  }

  try {
    const result = await pool.query(
      "UPDATE cylinders SET status = $1 WHERE serial_number = $2 RETURNING *",
      [status, serial_number]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Cylinder not found." });
    }

    // 1️⃣ Log the status update
    await logEvent("update_cylinder_status", req.user.id, {
      serial_number,
      new_status: status,
    });

    res.json({ message: "Cylinder status updated successfully." });
  } catch (error) {
    console.error("Update Cylinder Status Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Fetch Active Companies (Non-deleted)
app.get("/admin/companies", authenticateJWT, async (req, res) => {
  try {
    console.log("Fetching active companies...");
    const result = await pool.query(
      "SELECT * FROM companies WHERE deleted_at IS NULL"
    );
    console.log("✅ Companies fetched:", result.rows);
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Admin Companies Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Fetch Deleted Companies
// 🔹 Soft Delete Company & Move to `archived_companies`
app.post("/admin/delete-company", authenticateJWT, async (req, res) => {
  const { id } = req.body;
  const deletedBy = req.user.id; // Get the admin who deleted it

  try {
    // Retrieve the company details before deletion
    const companyResult = await pool.query(
      "SELECT * FROM companies WHERE id=$1",
      [id]
    );

    if (companyResult.rows.length === 0) {
      return res.status(404).json({ error: "Company not found" });
    }

    const { name, address, contact } = companyResult.rows[0];

    // Insert into `archived_companies`
    await pool.query(
      `INSERT INTO archived_companies (company_id, name, address, contact, deleted_by)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, name, address, contact, deletedBy]
    );

    // Remove from `companies` table
    await pool.query("DELETE FROM companies WHERE id=$1", [id]);

    res.sendStatus(200);
  } catch (error) {
    console.error("❌ Delete Company Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Add New Company
app.post("/admin/add-company", authenticateJWT, async (req, res) => {
  const { name, address, contact } = req.body;

  try {
    const result = await pool.query(
      "INSERT INTO companies (name, address, contact) VALUES ($1, $2, $3) RETURNING *",
      [name, address, contact]
    );
    res.status(201).json({ success: true, company: result.rows[0] });
  } catch (error) {
    console.error("❌ Add Company Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Update Company Details
app.put("/admin/update-company/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const { name, address, contact } = req.body;

  try {
    const result = await pool.query(
      "UPDATE companies SET name=$1, address=$2, contact=$3 WHERE id=$4 RETURNING *",
      [name, address, contact, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Company not found" });
    }

    // Retrieve the updated company details from the result
    const updatedCompany = result.rows[0];

    // Log the update event with a distinct event type "update_company"
    await logEvent("update_company", req.user.id, {
      company_id: updatedCompany.id,
      name: updatedCompany.name,
      address: updatedCompany.address,
      contact: updatedCompany.contact,
    });

    res.json({
      success: true,
      message: "Company updated successfully",
      company: updatedCompany,
    });
  } catch (error) {
    console.error("❌ Company Update Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Soft Delete Company (Move to Deleted)
app.post("/admin/delete-company", authenticateJWT, async (req, res) => {
  const { id } = req.body;
  const deletedBy = req.user.username; // Capture admin username for logs

  try {
    // Move company to deleted state
    await pool.query("UPDATE companies SET deleted_at=NOW() WHERE id=$1", [id]);

    // Log the deletion
    await pool.query(
      "INSERT INTO deleted_companies_log (company_id, deleted_by, deleted_at) VALUES ($1, $2, NOW())",
      [id, deletedBy]
    );
    // 1️⃣ Log the event
    await logEvent("delete_company", req.user.id, {
      company_id: id,
    });

    res.json({ success: true, message: "Company deleted successfully" });
  } catch (error) {
    console.error("❌ Delete Company Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});
// 🔹 Fetch Archived Companies (Previously Deleted Companies)
app.get("/admin/deleted-companies", authenticateJWT, async (req, res) => {
  try {
    console.log("Fetching deleted companies...");

    const result = await pool.query(
      "SELECT * FROM archived_companies ORDER BY deleted_at DESC"
    );

    console.log("✅ Deleted Companies fetched:", result.rows);
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Deleted Companies Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// 🔹 Recover Deleted Company
app.post("/admin/recover-company", authenticateJWT, async (req, res) => {
  const { id } = req.body;

  try {
    const deletedCompany = await pool.query(
      "SELECT * FROM archived_companies WHERE id = $1",
      [id]
    );

    if (deletedCompany.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Company not found in deleted records" });
    }
    // 1️⃣ Log the event
    await logEvent("recover_company", req.user.id, {
      company_id: id,
    });
    const { name, address, contact } = deletedCompany.rows[0];

    // ✅ Let PostgreSQL generate a NEW unique ID
    const newCompany = await pool.query(
      "INSERT INTO companies (name, address, contact) VALUES ($1, $2, $3) RETURNING id",
      [name, address, contact]
    );

    await pool.query("DELETE FROM archived_companies WHERE id = $1", [id]);

    res.json({
      message: "Company restored successfully!",
      new_id: newCompany.rows[0].id,
    });
  } catch (error) {
    console.error("❌ Restore Company Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

//reports
//reports

app.get("/admin/holding-report", authenticateJWT, async (req, res) => {
  try {
    // Optional filters from query parameters
    let { company, start, end } = req.query;
    let conditions = [];
    let params = [];

    // Filter by company name if provided
    if (company) {
      conditions.push(`comp.name ILIKE $${params.length + 1}`);
      params.push(`%${company}%`);
    }
    // Filter by holding date range (using cylinders.created_at here)
    if (start && end) {
      conditions.push(
        `c.created_at BETWEEN $${params.length + 1} AND $${params.length + 2}`
      );
      params.push(start, end);
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const query = `
      SELECT 
        comp.name AS company_name,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity::text, ' ', gp.measurement_unit) AS product_label,
        MIN(c.created_at) AS holding_date,
        COUNT(c.id) AS total_cylinders,
        ARRAY_AGG(c.serial_number) AS cylinders
      FROM cylinders c
      JOIN companies comp ON c.company_id = comp.id
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      ${whereClause}
      GROUP BY comp.name, product_label
      ORDER BY comp.name, product_label;
    `;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error("Holding Report Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get(
  "/admin/reports/cylinder-movement",
  authenticateJWT,
  async (req, res) => {
    try {
      let { start, end, search, sortBy, sortOrder } = req.query;

      let query = `
      SELECT 
        t.cylinder_id, 
        t.action, 
        u.username AS performed_by, 
        t.timestamp
      FROM transactions t
      JOIN users u ON t.user_id = u.id
      WHERE 1 = 1
    `;

      let values = [];

      // 🔹 Date filter
      if (start && end) {
        query += ` AND t.timestamp BETWEEN $${values.length + 1} AND $${
          values.length + 2
        }`;
        values.push(start, end);
      }

      // 🔹 Search filter (filtering by cylinder ID or action type)
      if (search) {
        query += ` AND (
        CAST(t.cylinder_id AS TEXT) LIKE $${values.length + 1}
        OR LOWER(t.action) LIKE LOWER($${values.length + 1})
      )`;
        values.push(`%${search}%`);
      }

      // 🔹 Sorting logic
      if (sortBy && ["cylinder_id", "timestamp", "action"].includes(sortBy)) {
        query += ` ORDER BY ${sortBy} ${sortOrder === "desc" ? "DESC" : "ASC"}`;
      } else {
        query += ` ORDER BY t.timestamp DESC`; // Default sorting by latest
      }

      const result = await pool.query(query, values);
      res.json(result.rows);
    } catch (error) {
      console.error("❌ Cylinder Movement Report Error:", error);
      res.status(500).json({ error: "Database error", details: error.message });
    }
  }
);

app.get("/admin/reports/combined", authenticateJWT, async (req, res) => {
  try {
    // Extract filter parameters from query string
    let {
      start,
      end,
      search,
      sortBy,
      sortOrder,
      gasType,
      company,
      worker,
      productType,
    } = req.query;
    let values = [];
    let query = `
      SELECT 
        t.id AS transaction_id,
        t.action,
        u.username AS performed_by,
        t.timestamp,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS product_label,
        comp.name AS company_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.id
      LEFT JOIN cylinders c ON t.cylinder_id = c.id
      LEFT JOIN gas_products gp ON c.gas_product_id = gp.id
      LEFT JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      LEFT JOIN gas_types gt ON gst.gas_type_id = gt.id
      LEFT JOIN companies comp ON t.company_id = comp.id
      WHERE 1=1
    `;

    // Date range filter
    if (start && end) {
      query += ` AND t.timestamp BETWEEN $${values.length + 1} AND $${
        values.length + 2
      }`;
      values.push(start, end);
    }

    // Search filter (applied to cylinder, action, or worker)
    if (search) {
      query += ` AND (CAST(t.id AS TEXT) ILIKE $${values.length + 1}
                   OR LOWER(t.action) ILIKE LOWER($${values.length + 1})
                   OR LOWER(u.username) ILIKE LOWER($${values.length + 1}))`;
      values.push(`%${search}%`);
    }

    // Gas type filter (applied to the computed product label)
    if (gasType) {
      query += ` AND gt.name ILIKE $${values.length + 1}`;
      values.push(`%${gasType}%`);
    }

    // Product type filter (applied to computed product label)
    if (productType) {
      query += ` AND (CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit)) ILIKE $${
        values.length + 1
      }`;
      values.push(`%${productType}%`);
    }

    // Company filter
    if (company) {
      query += ` AND comp.name ILIKE $${values.length + 1}`;
      values.push(`%${company}%`);
    }

    // Worker filter
    if (worker) {
      query += ` AND u.username ILIKE $${values.length + 1}`;
      values.push(`%${worker}%`);
    }

    // Sorting logic
    const allowedSortColumns = [
      "transaction_id",
      "timestamp",
      "action",
      "product_label",
      "company_name",
      "performed_by",
    ];
    if (sortBy && allowedSortColumns.includes(sortBy)) {
      query += ` ORDER BY ${sortBy} ${sortOrder === "desc" ? "DESC" : "ASC"}`;
    } else {
      query += ` ORDER BY t.timestamp DESC`;
    }

    const transactionsResult = await pool.query(query, values);

    // Build summary queries (for total, unique cylinders, etc.)
    const summaryQuery = `
      SELECT 
        COUNT(*) AS total_transactions, 
        COUNT(DISTINCT cylinder_id) AS unique_cylinders, 
        MAX(timestamp) AS latest_activity
      FROM transactions;
    `;
    const actionBreakdownQuery = `
      SELECT action, COUNT(*) AS count 
      FROM transactions 
      GROUP BY action 
      ORDER BY count DESC;
    `;

    const [summaryResult, actionBreakdownResult] = await Promise.all([
      pool.query(summaryQuery),
      pool.query(actionBreakdownQuery),
    ]);

    const summary = {
      total_transactions: summaryResult.rows[0].total_transactions,
      unique_cylinders: summaryResult.rows[0].unique_cylinders,
      latest_activity: summaryResult.rows[0].latest_activity,
      action_breakdown: actionBreakdownResult.rows,
    };

    res.json({
      transactions: transactionsResult.rows,
      summary,
    });
  } catch (error) {
    console.error("❌ Combined Reports Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Endpoint for product types (if product type is a combination of gas_type and size)
app.get("/admin/products", authenticateJWT, async (req, res) => {
  try {
    const query = `
      SELECT 
        gp.id,  
        gp.gas_sub_type_id,
        gp.capacity,
        gp.measurement_unit,
        gp.description,
        gp.created_at,
        gp.price,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS label
      FROM gas_products gp
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      ORDER BY gp.created_at DESC;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching admin products:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/reports/gas-sub-type", authenticateJWT, async (req, res) => {
  const { gasSubType } = req.query;
  if (!gasSubType) {
    return res
      .status(400)
      .json({ error: "gasSubType query parameter is required" });
  }

  // Define a low-stock threshold if needed; here it is 5.
  const LOW_STOCK_THRESHOLD = 5;

  try {
    const query = `
      SELECT 
        gst.name AS gas_sub_type,
        COUNT(c.id) AS total_cylinders,
        COUNT(c.id) FILTER (WHERE c.status = 'available') AS available_count,
        COUNT(c.id) FILTER (WHERE c.status = 'dispatched') AS dispatched_count,
        COUNT(c.id) FILTER (WHERE c.status = 'refilling') AS refilling_count,
        COUNT(c.id) FILTER (WHERE c.status = 'empty') AS empty_count,
        CASE 
          WHEN COUNT(c.id) FILTER (WHERE c.status = 'available') < $2 THEN 'Reorder Now'
          ELSE '-'
        END AS reorder_recommendation
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      WHERE gst.name ILIKE $1
      GROUP BY gst.name
      ORDER BY gst.name;
    `;
    const result = await pool.query(query, [
      `%${gasSubType}%`,
      LOW_STOCK_THRESHOLD,
    ]);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching gas sub type report", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get(
  "/admin/reports/gas-type-summary",
  authenticateJWT,
  async (req, res) => {
    try {
      const query = `
      SELECT 
        gt.id,
        gt.name,
        COUNT(c.id) AS total_count,
        COUNT(c.id) FILTER (WHERE c.status = 'dispatched') AS dispatched_count,
        COUNT(c.id) FILTER (WHERE c.status = 'empty') AS empty_count
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      GROUP BY gt.id, gt.name
      ORDER BY gt.name;
    `;
      const result = await pool.query(query);
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching gas type summary:", error);
      res.status(500).json({ error: "Database error", details: error.message });
    }
  }
);

app.get("/admin/product-types", authenticateJWT, async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT 
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity::text, ' ', gp.measurement_unit) AS product_type
      FROM gas_products gp
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      ORDER BY product_type;
    `;
    const result = await pool.query(query);
    // Return an array of product type strings
    res.json(result.rows.map((row) => row.product_type));
  } catch (error) {
    console.error("Error fetching product types:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/reports/gas-type", authenticateJWT, async (req, res) => {
  const { gasType } = req.query;
  if (!gasType) {
    return res
      .status(400)
      .json({ error: "gasType query parameter is required" });
  }
  try {
    const query = `
      SELECT 
        gt.name as gas_type,
        COUNT(c.id) AS total_cylinders,
        COUNT(c.id) FILTER (WHERE c.status = 'available') AS available_count,
        COUNT(c.id) FILTER (WHERE c.status = 'dispatched') AS dispatched_count,
        COUNT(c.id) FILTER (WHERE c.status = 'refilling') AS refilling_count,
        COUNT(c.id) FILTER (WHERE c.status = 'empty') AS empty_count
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      WHERE LOWER(gt.name) = LOWER($1)
      GROUP BY gt.name;
    `;
    const result = await pool.query(query, [gasType]);
    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "No data found for the specified gas type" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching gas type report:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/reports/company-wise", authenticateJWT, async (req, res) => {
  // Get start and end dates from query; if missing, default to last 1 month.
  let { start, end } = req.query;
  if (!start || !end) {
    const now = new Date();
    const oneMonthAgo = new Date();
    oneMonthAgo.setMonth(now.getMonth() - 1);
    start = oneMonthAgo.toISOString();
    end = now.toISOString();
  }
  try {
    const query = `
      SELECT 
        comp.id AS company_id,
        comp.name AS company_name,
        COUNT(t.id) AS total_transactions,
        COUNT(CASE WHEN t.action = 'dispatch' THEN 1 END) AS dispatched,
        COUNT(CASE WHEN t.action = 'receive_empty' THEN 1 END) AS received_empty,
        COUNT(CASE WHEN t.action = 'receive_filled' THEN 1 END) AS received_filled,
        COUNT(CASE WHEN t.action = 'refill' THEN 1 END) AS refilled,
        COUNT(DISTINCT c.serial_number) AS unique_cylinders
      FROM companies comp
      LEFT JOIN transactions t ON comp.id = t.company_id
      LEFT JOIN cylinders c ON t.cylinder_id = c.id
      WHERE t.timestamp BETWEEN $1 AND $2
      GROUP BY comp.id, comp.name
      ORDER BY comp.name;
    `;
    const result = await pool.query(query, [start, end]);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching company-wise report:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/reports/detailed", authenticateJWT, async (req, res) => {
  const { start, end } = req.query;
  if (!start || !end) {
    return res.status(400).json({ error: "Start and end dates are required" });
  }
  try {
    // Adjust the query below based on your actual schema.
    // This query assumes:
    // - Each transaction row corresponds to one cylinder transfer.
    // - The cylinders table has columns: serial_number, gas_type, size.
    // - The companies table has a name column.
    // - The users table contains username.
    const query = `
      SELECT 
        t.id,
        u.username AS worker,
        c.serial_number AS cylinder,
        c.gas_type,
        c.size,
        (c.gas_type || ' ' || c.size) AS product_type,
        comp.name AS client,
        t.action,
        t.timestamp
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.id
      LEFT JOIN cylinders c ON t.cylinder_id = c.id
      LEFT JOIN companies comp ON t.company_id = comp.id
      WHERE t.timestamp BETWEEN $1 AND $2
      ORDER BY t.timestamp DESC
    `;
    const result = await pool.query(query, [start, end]);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching detailed reports:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Endpoint for gas types
app.get("/admin/gas-types", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name FROM gas_types ORDER BY name"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching gas types:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.put("/admin/update-gas-type", authenticateJWT, async (req, res) => {
  const { id, name } = req.body;
  if (!id || !name) {
    return res.status(400).json({ error: "id and name are required" });
  }
  try {
    const result = await pool.query(
      "UPDATE gas_types SET name = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
      [name, id]
    );
    res.json({
      message: "Gas type updated successfully",
      gas_type: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating gas type:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.delete("/admin/delete-gas-type", authenticateJWT, async (req, res) => {
  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ error: "id is required" });
  }
  try {
    await pool.query("DELETE FROM gas_types WHERE id = $1", [id]);
    res.json({ message: "Gas type deleted successfully" });
  } catch (error) {
    console.error("Error deleting gas type:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.put("/admin/update-gas-sub-type", authenticateJWT, async (req, res) => {
  const { id, name } = req.body;
  if (!id || !name) {
    return res.status(400).json({ error: "id and name are required" });
  }
  try {
    const result = await pool.query(
      "UPDATE gas_sub_types SET name = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
      [name, id]
    );
    res.json({
      message: "Gas sub type updated successfully",
      gas_sub_type: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating gas sub type:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.delete("/admin/delete-gas-sub-type", authenticateJWT, async (req, res) => {
  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ error: "id is required" });
  }
  try {
    await pool.query("DELETE FROM gas_sub_types WHERE id = $1", [id]);
    res.json({ message: "Gas sub type deleted successfully" });
  } catch (error) {
    console.error("Error deleting gas sub type:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Add this new endpoint in your Express server code:
app.get("/admin/gas-sub-types", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM gas_sub_types ORDER BY id");
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching gas sub types:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Endpoint to fetch gas products filtered by gas_type_id
app.get("/admin/gas-products", authenticateJWT, async (req, res) => {
  const { gas_type_id } = req.query;
  try {
    let query = `
      SELECT 
        gp.id, 
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS label
      FROM gas_products gp
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
    `;
    const params = [];
    if (gas_type_id) {
      query += ` WHERE gt.id = $1 `;
      params.push(gas_type_id);
    }
    query += ` ORDER BY label`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching gas products:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Endpoint to add a new user (worker or admin)
app.post("/admin/add-user", authenticateJWT, async (req, res) => {
  // Optional: Verify that the requester is an admin
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    // Insert the new user into the users table
    await pool.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
      [username, hashedPassword, role]
    );
    res.json({ message: "User added successfully!" });
  } catch (error) {
    console.error("Error adding user:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get(
  "/admin/reports/cylinder-movement-summary",
  authenticateJWT,
  async (req, res) => {
    try {
      // Fetch summary data
      const summaryQuery = `
      SELECT 
        COUNT(*) AS total_transactions, 
        COUNT(DISTINCT cylinder_id) AS unique_cylinders, 
        MAX(timestamp) AS latest_activity
      FROM transactions;
    `;

      const actionBreakdownQuery = `
      SELECT action, COUNT(*) AS count 
      FROM transactions 
      GROUP BY action 
      ORDER BY count DESC;
    `;

      // Execute queries
      const summaryResult = await pool.query(summaryQuery);
      const actionBreakdownResult = await pool.query(actionBreakdownQuery);

      res.json({
        total_transactions: summaryResult.rows[0].total_transactions,
        unique_cylinders: summaryResult.rows[0].unique_cylinders,
        latest_activity: summaryResult.rows[0].latest_activity,
        action_breakdown: actionBreakdownResult.rows,
      });
    } catch (error) {
      console.error("❌ Cylinder Movement Summary Error:", error);
      res.status(500).json({ error: "Database error", details: error.message });
    }
  }
);
app.get("/admin/audit-logs", authenticateJWT, async (req, res) => {
  // Allow only owner users to access audit logs.
  if (req.user.role !== "owner") {
    return res.status(403).json({ error: "Access denied" });
  }

  // Get optional filters and pagination parameters from query string.
  const { start, end, search, offset = 0, limit = 100 } = req.query;
  let query = "SELECT * FROM audit_logs";
  let values = [];
  let conditions = [];

  if (start && end) {
    conditions.push(
      `event_timestamp BETWEEN $${values.length + 1} AND $${values.length + 2}`
    );
    values.push(start, end);
  }

  if (search) {
    conditions.push(`event_type ILIKE $${values.length + 1}`);
    values.push(`%${search}%`);
  }

  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY event_timestamp DESC";
  query += ` LIMIT $${values.length + 1} OFFSET $${values.length + 2}`;
  values.push(limit, offset);

  try {
    const result = await pool.query(query, values);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching audit logs:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

//product manuplection

app.post("/admin/add-gas-type", authenticateJWT, async (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Gas type name is required" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO gas_types (name, created_at) 
       VALUES ($1, NOW()) RETURNING *`,
      [name]
    );
    res.json({
      message: "Gas type added successfully",
      gas_type: result.rows[0],
    });
  } catch (error) {
    console.error("Error adding gas type:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/admin/add-gas-sub-type", authenticateJWT, async (req, res) => {
  const { gas_type_id, name } = req.body;

  if (!gas_type_id || !name) {
    return res
      .status(400)
      .json({ error: "Gas type ID and sub type name are required" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO gas_sub_types (gas_type_id, name, created_at)
       VALUES ($1, $2, NOW()) RETURNING *`,
      [gas_type_id, name]
    );
    res.json({
      message: "Gas sub type added successfully",
      gas_sub_type: result.rows[0],
    });
  } catch (error) {
    console.error("Error adding gas sub type:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/admin/add-product", authenticateJWT, async (req, res) => {
  const { gas_sub_type_id, capacity, measurement_unit, description, price } =
    req.body;

  if (
    !gas_sub_type_id ||
    !capacity ||
    !measurement_unit ||
    price === undefined
  ) {
    return res.status(400).json({
      error:
        "Missing required fields: gas_sub_type_id, capacity, measurement_unit, price",
    });
  }

  try {
    // Retrieve the gas sub type name for computing the product name.
    const gasSubTypeResult = await pool.query(
      "SELECT name FROM gas_sub_types WHERE id = $1",
      [gas_sub_type_id]
    );
    if (gasSubTypeResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid gas_sub_type_id" });
    }

    const gasSubTypeName = gasSubTypeResult.rows[0].name;
    // Compute the product name (e.g., "Industrial 50L")
    const computedName = `${gasSubTypeName} ${capacity}${measurement_unit}`;

    const result = await pool.query(
      `INSERT INTO gas_products (gas_sub_type_id, capacity, measurement_unit, description, price, name, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
      [
        gas_sub_type_id,
        capacity,
        measurement_unit,
        description || "",
        price,
        computedName,
      ]
    );
    res.json({
      message: "Gas product added successfully",
      gas_product: result.rows[0],
    });
  } catch (error) {
    console.error("Error adding gas product:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Daily Stock Report JSON Endpoint
app.get("/admin/stock-report", authenticateJWT, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const offset = parseInt(req.query.offset) || 0;

    // Data query with pagination.
    const dataQuery = `
      SELECT 
        gp.id,
        CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit) AS product_name,
        COUNT(c.id) AS stock_count
      FROM cylinders c
      JOIN gas_products gp ON c.gas_product_id = gp.id
      JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
      JOIN gas_types gt ON gst.gas_type_id = gt.id
      GROUP BY gp.id, product_name
      ORDER BY product_name
      LIMIT $1 OFFSET $2;
    `;

    // Count query for total number of groups.
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM (
        SELECT gp.id
        FROM cylinders c
        JOIN gas_products gp ON c.gas_product_id = gp.id
        JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
        JOIN gas_types gt ON gst.gas_type_id = gt.id
        GROUP BY gp.id, CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity, ' ', gp.measurement_unit)
      ) AS sub;
    `;

    const dataResult = await pool.query(dataQuery, [limit, offset]);
    const countResult = await pool.query(countQuery);
    const total = parseInt(countResult.rows[0].total, 10);

    // Map the rows to include placeholders for yesterday's closing and today's opening.
    const report = dataResult.rows.map((row) => ({
      product_name: row.product_name,
      yesterday_closing: row.stock_count, // Placeholder
      today_opening: row.stock_count, // Placeholder
    }));

    res.json({ total, rows: report });
  } catch (error) {
    console.error("Error fetching stock report:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Create a new maintenance log
app.post("/maintenance-logs", authenticateJWT, async (req, res) => {
  const {
    cylinder_id,
    maintenance_date,
    maintenance_type,
    description,
    performed_by,
    next_inspection_date,
  } = req.body;
  if (!cylinder_id || !maintenance_date || !maintenance_type) {
    return res.status(400).json({ error: "Missing required fields." });
  }
  try {
    const result = await pool.query(
      `INSERT INTO maintenance_logs (cylinder_id, maintenance_date, maintenance_type, description, performed_by, next_inspection_date, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
       RETURNING *`,
      [
        cylinder_id,
        maintenance_date,
        maintenance_type,
        description || "",
        performed_by || "",
        next_inspection_date || null,
      ]
    );
    res.json({
      message: "Maintenance log created successfully.",
      maintenanceLog: result.rows[0],
    });
  } catch (error) {
    console.error("Error creating maintenance log:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Maintenance Request Endpoint
app.post("/maintenance-request", authenticateJWT, async (req, res) => {
  const { cylinderIds, description } = req.body;

  // Validate input
  if (!Array.isArray(cylinderIds) || cylinderIds.length === 0) {
    return res.status(400).json({ error: "No cylinder IDs provided." });
  }
  if (!description || description.trim() === "") {
    return res.status(400).json({ error: "Maintenance description required." });
  }

  try {
    // Fetch cylinders by serial numbers
    const cylindersRes = await pool.query(
      "SELECT serial_number, id, status FROM cylinders WHERE serial_number = ANY($1::text[])",
      [cylinderIds]
    );
    if (cylindersRes.rows.length === 0) {
      return res.status(400).json({ error: "No matching cylinders found." });
    }

    // Filter out those that are already under maintenance (either in-process or maintenance)
    const alreadyMaintenance = cylindersRes.rows.filter(
      (row) =>
        row.status.toLowerCase() === "maintenance" ||
        row.status.toLowerCase() === "in-process"
    );
    const toUpdate = cylindersRes.rows.filter(
      (row) =>
        row.status.toLowerCase() !== "maintenance" &&
        row.status.toLowerCase() !== "in-process"
    );

    // If none remain to update, return an error
    if (toUpdate.length === 0) {
      return res.status(400).json({
        error: "All provided cylinders are already under maintenance.",
      });
    }

    // Update status for the cylinders that are not already in maintenance
    const updateSerials = toUpdate.map((row) => row.serial_number);
    await pool.query(
      "UPDATE cylinders SET status = 'maintenance' WHERE serial_number = ANY($1::text[])",
      [updateSerials]
    );

    // Get the numeric IDs for the cylinders to update
    const cylinderNumericIds = toUpdate.map((row) => row.id);

    // Insert maintenance log records for each updated cylinder.
    // We record the current time as maintenance_start and requested_at.
    const maintenanceQuery = `
      INSERT INTO maintenance_logs 
        (worker_id, cylinder_id, description, maintenance_start, status, requested_at, performed_by)
      SELECT 
        $1, unnest($2::int[]), $3, NOW(), 'in-process', NOW(), $4
      RETURNING id, cylinder_id
    `;
    const maintenanceValues = [
      req.user.id,
      cylinderNumericIds,
      description,
      req.user.username,
    ];
    const maintenanceRes = await pool.query(
      maintenanceQuery,
      maintenanceValues
    );

    res.json({
      message: "Maintenance request submitted successfully!",
      maintenanceLogs: maintenanceRes.rows,
      skippedCylinders: alreadyMaintenance.map((row) => row.serial_number),
    });
  } catch (error) {
    console.error("Maintenance Request Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Get all maintenance logs
// Get all maintenance logs
app.get("/maintenance-logs", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ml.*, c.serial_number 
       FROM maintenance_logs ml 
       JOIN cylinders c ON ml.cylinder_id = c.id
       ORDER BY ml.requested_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching maintenance logs:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/cylinder-status/:serial", authenticateJWT, async (req, res) => {
  const { serial } = req.params;
  try {
    const result = await pool.query(
      "SELECT status FROM cylinders WHERE serial_number = $1",
      [serial]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Cylinder not found" });
    }
    res.json({ status: result.rows[0].status });
  } catch (error) {
    console.error("Error checking cylinder status:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.post("/maintenance-complete", authenticateJWT, async (req, res) => {
  const { cylinderIds, description } = req.body;
  if (!Array.isArray(cylinderIds) || cylinderIds.length === 0) {
    return res.status(400).json({ error: "No cylinder IDs provided" });
  }
  try {
    // Check if all cylinders are currently under maintenance.
    const checkResult = await pool.query(
      "SELECT serial_number FROM cylinders WHERE serial_number = ANY($1::text[]) AND status != 'maintenance'",
      [cylinderIds]
    );
    if (checkResult.rows.length > 0) {
      const notMaint = checkResult.rows
        .map((row) => row.serial_number)
        .join(", ");
      return res
        .status(400)
        .json({ error: `Cylinders not under maintenance: ${notMaint}` });
    }
    // Update the cylinders to mark them as available.
    await pool.query(
      "UPDATE cylinders SET status = 'available' WHERE serial_number = ANY($1::text[])",
      [cylinderIds]
    );
    // Update the maintenance logs for these cylinders that are still marked as 'in-process'
    const updateLogQuery = `
      UPDATE maintenance_logs
      SET maintenance_end = NOW(), status = 'maintenance done', description = $2, performed_by = $3
      WHERE cylinder_id IN (
        SELECT id FROM cylinders WHERE serial_number = ANY($1::text[])
      ) AND status = 'in-process'
      RETURNING cylinder_id
    `;
    const updateLogResult = await pool.query(updateLogQuery, [
      cylinderIds,
      description,
      req.user.username,
    ]);
    res.json({
      message: "Maintenance completed for selected cylinders.",
      updatedMaintenance: updateLogResult.rows,
    });
  } catch (error) {
    console.error("Maintenance Complete Error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/maintenance-cylinders", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT serial_number FROM cylinders WHERE status = 'maintenance'"
    );
    res.json(result.rows); // Array of objects: [{ serial_number: "CYL1010" }, ...]
  } catch (error) {
    console.error("Error fetching maintenance cylinders:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.get("/admin/reports/refill-summary", authenticateJWT, async (req, res) => {
  try {
    const todayQuery = `
      SELECT COUNT(*) AS refilled_today
      FROM transactions
      WHERE action = 'refill'
        AND timestamp >= date_trunc('day', CURRENT_TIMESTAMP)
        AND timestamp < date_trunc('day', CURRENT_TIMESTAMP) + INTERVAL '1 day';
    `;
    const monthQuery = `
      SELECT COUNT(*) AS refilled_this_month
      FROM transactions
      WHERE action = 'refill'
        AND timestamp >= date_trunc('month', CURRENT_TIMESTAMP)
        AND timestamp < date_trunc('month', CURRENT_TIMESTAMP) + INTERVAL '1 month';
    `;
    const todayResult = await pool.query(todayQuery);
    const monthResult = await pool.query(monthQuery);

    res.json({
      refilled_today: todayResult.rows[0].refilled_today,
      refilled_this_month: monthResult.rows[0].refilled_this_month,
    });
  } catch (error) {
    console.error("Error fetching refill summary:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// testing code

app.get("/product-name/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params; // now 'id' is the cylinder serial number (e.g., "CYL1010")
  try {
    const result = await pool.query(
      `SELECT 
         CONCAT(gt.name, ' ', gst.name, ' ', gp.capacity::text, ' ', gp.measurement_unit) AS productlabel
       FROM cylinders c
       JOIN gas_products gp ON c.gas_product_id = gp.id
       JOIN gas_sub_types gst ON gp.gas_sub_type_id = gst.id
       JOIN gas_types gt ON gst.gas_type_id = gt.id
       WHERE c.serial_number = $1`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Cylinder not found" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching product name:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
