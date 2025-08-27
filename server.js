const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// 🔹 Connect to MongoDB (use free MongoDB Atlas or local MongoDB)
mongoose.connect("mongodb://127.0.0.1:27017/pixelpop", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// 🔹 User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", UserSchema);

// 🔹 Signup API
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
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
  const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ error: "User not found" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ id: user._id }, "secret123", { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// 🔹 Protected API Example
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, "secret123");
    res.json({ message: "Protected data", userId: decoded.id });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// 🔹 Start Server
app.listen(5000, () => console.log("Backend running on http://localhost:5000"));
