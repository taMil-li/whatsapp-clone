const express = require("express");
const http = require("http");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const connectDB = require("./db");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
app.use(express.json());

// CORS - allow frontend origin
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

// Connect to MongoDB
const MONGO_URI =
  "mongodb+srv://tamildeveloper2007_db_user:9GycWXx0AH79jF0m@whatsapp-clone-db.jbodsmz.mongodb.net/?retryWrites=true&w=majority&appName=whatsapp-clone-db"; //process.env.MONGO_URI;
connectDB(MONGO_URI);

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: false }, // optional if you prefer email-based
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});

const messageSchema = new mongoose.Schema({
  sender_id: {
    type: String,
    required: true,
  },
  receiver_id: {
    type: String,
    required: true,
  },
  content: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// JWT config
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

function generateToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

// Auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token provided" });
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ message: "Invalid auth format" });

  const token = parts[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // contains id, email
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res
        .status(400)
        .json({ message: "name, email, password required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hash });
    await user.save();

    return res.json({ message: "Signup successful" });
  } catch (err) {
    console.error("Signup err:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user);

    // return user object with id field (string) to match frontend expectation
    const userObj = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      created_at: user.created_at,
    };

    return res.json({ token, user: userObj });
  } catch (err) {
    console.error("Login err:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Get all users (protected) - returns minimal info
app.get("/users", async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }).sort({ name: 1 });
    const result = users.map((u) => ({
      id: u._id.toString(),
      name: u.name,
      email: u.email,
      created_at: u.created_at,
    }));
    res.json(result);
  } catch (err) {
    console.error("Get users err:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Create a message (also used by socket, but keep REST for direct POST)
app.post("/messages", async (req, res) => {
  try {
    const { sender_id, receiver_id, content } = req.body;
    if (!sender_id || !receiver_id || !content)
      return res.status(400).json({ message: "Missing fields" });

    const msg = new Message({
      sender_id,
      receiver_id,
      content,
    });
    await msg.save();

    // populate sender/receiver ids as strings for frontend convenience
    const out = {
      _id: msg._id.toString(),
      sender_id: msg.sender_id.toString(),
      receiver_id: msg.receiver_id.toString(),
      content: msg.content.toString(),
      created_at: msg.created_at,
    };

    // Note: socket emits happen in socket block below; this REST route just saves and returns
    res.json(out);
  } catch (err) {
    console.error("Post message err:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get messages between two users (protected)
app.get("/messages/:user1/:user2", async (req, res) => {
  try {
    const { user1, user2 } = req.params;

    // Validate objectId format
    if (
      !user1 ||
      !user2
    ) {
      return res.status(400).json({ message: "Invalid user ids" });
    }

    const msgs = await Message.find({
      $or: [
        { sender_id: String(user1), receiver_id: String(user2) },
        { sender_id: String(user2), receiver_id: String(user1) },
      ],
    }).sort({ created_at: 1 });

    const out = msgs.map((m) => ({
      _id: m._id.toString(),
      sender_id: m.sender_id.toString(),
      receiver_id: m.receiver_id.toString(),
      content: m.content,
      created_at: m.created_at,
    }));

    res.json(out);
  } catch (err) {
    console.error("Get messages err:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Optional: get a single message
app.get("/message/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid id" });

    const m = await Message.findById(id);
    if (!m) return res.status(404).json({ message: "Not found" });

    res.json({
      _id: m._id.toString(),
      sender_id: m.sender_id.toString(),
      receiver_id: m.receiver_id.toString(),
      content: m.content,
      created_at: m.created_at,
    });
  } catch (err) {
    console.error("Get single message err:", err);
    res.status(500).json({ message: "Server error" });
  }
});

///////////////////////
// Socket.IO real-time
///////////////////////
const PORT = process.env.PORT || 3001;
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

// Map userId (string) -> socket.id
const onlineUsers = new Map();

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("register", (userId) => {
    if (!userId) return;
    onlineUsers.set(String(userId), socket.id);
    console.log("Registered user", userId, "->", socket.id);
  });

  socket.on("sendMessage", async (data) => {
    try {
      const { sender_id, receiver_id, content } = data;
      if (!sender_id || !receiver_id || !content) return;

      if (
        !mongoose.Types.ObjectId.isValid(sender_id) ||
        !mongoose.Types.ObjectId.isValid(receiver_id)
      ) {
        console.error("Invalid ObjectId in sendMessage:", data);
        return socket.emit("error", {
          message: "Invalid sender_id or receiver_id",
        });
      }

      // Save to DB
      const msg = new Message({ sender_id, receiver_id, content });
      await msg.save();

      const out = {
        _id: msg._id.toString(),
        sender_id: msg.sender_id.toString(),
        receiver_id: msg.receiver_id.toString(),
        content: msg.content,
        created_at: msg.created_at,
      };

      // Emit to receiver if online
      const recvSocketId = onlineUsers.get(String(receiver_id));
      if (recvSocketId) {
        io.to(recvSocketId).emit("receiveMessage", out);
      }

      // Acknowledge sender
      socket.emit("messageSaved", out);
    } catch (err) {
      console.error("Socket sendMessage err:", err);
      socket.emit("error", { message: "Failed to send message" });
    }
  });

  socket.on("disconnect", () => {
    // remove any entries that had this socket id
    for (const [uid, sid] of onlineUsers.entries()) {
      if (sid === socket.id) onlineUsers.delete(uid);
    }
    console.log("Socket disconnected:", socket.id);
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
