const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
// Use process.env.PORT for Render deployment, or 5000 for local development
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

// 🔹 Connect to MongoDB Atlas
// The connection string is now pulled from an environment variable for security
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("Connected to MongoDB!");
}).catch(err => {
  console.error("Could not connect to MongoDB:", err);
});

// 🔹 User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

// 🔹 Signup API
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword });
    res.json({ message: "User created successfully!" });
  } catch (err) {
    res.status(400).json({ error: "User already exists!" });
  }
});

// 🔹 Login API
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }
  const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ error: "User not found" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "secret123", { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// 🔹 Protected API Example
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET || "secret123");
    res.json({ message: "Protected data", userId: decoded.id });
  } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
});

// 🔹 Start Server
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));