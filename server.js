const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
// Use process.env.PORT for Render deployment, or 5000 for local development
const PORT = process.env.PORT || 5000;

// Middleware setup
app.use(express.json()); // Allows the app to parse JSON from incoming requests
app.use(cors()); // Enables Cross-Origin Resource Sharing, allowing your frontend to connect

// 🔹 Connect to MongoDB Atlas
// The connection string is pulled from an environment variable for security
// Ensure you have set MONGODB_URI on your Render dashboard
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("Connected to MongoDB!");
}).catch(err => {
  console.error("Could not connect to MongoDB:", err);
});

// 🔹 Define the User Schema and Model
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

// 🔹 Root API endpoint
app.get("/", (req, res) => {
  res.send("Backend server is running!");
});

// 🔹 Signup API
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword });
    res.status(201).json({ message: "User created successfully!" });
  } catch (err) {
    // This will catch the duplicate key error if the username already exists
    res.status(400).json({ error: "User already exists!" });
  }
});

// 🔹 Login API
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." });
    }
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid password" });
    }

    // You should use a strong, secret key for JWT_SECRET in production
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "secret123", { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: "An error occurred during login." });
  }
});

// 🔹 Protected API Example
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    // Remove "Bearer " prefix from the token string
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET || "secret123");
    res.json({ message: "Protected data", userId: decoded.id });
  } catch (err) {
      res.status(401).json({ error: "Invalid token" });
  }
});

// 🔹 Start Server
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
