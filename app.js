import express from "express";
import mongoose from "mongoose";
import userModel from "./models/user.js";
import postModel from "./models/post.js";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import postMessgeModel from "./models/postMessage.js";
import multer from "multer";
import propertyModel from "./models/postProperty.js";
import propertyRequestModel from "./models/propertyRequest.js";
import clientNeedModel from "./models/clientNeed.js";
import compression from "compression";
import dotenv from "dotenv";
import { google } from "./oauth.js";
import { generateState, generateCodeVerifier } from "arctic";
import axios from "axios";

dotenv.config();

// Database Connection with more logging
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB Successfully");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1); // Crash and restart if DB fails
  }
};
connectDB();

const app = express();

app.use(compression());
app.set("trust proxy", 1); // Trust first proxy (Railway/Vercel)
app.use(express.json());
app.use(cookieParser());

// Fixed CORS for Production
app.use(
  cors({
    origin: "https://uniwebproj.vercel.app",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

const upload = multer({ storage: multer.memoryStorage() });
const Secret_key = process.env.JWT_SECRET || "abdullah123@!";

// --- Auth Routes Optimized ---

app.post("/register", async (req, res) => {
  try {
    const { full_name, email, password } = req.body;
    const check = await userModel.findOne({ email });

    if (check) {
      return res.status(400).json({ message: "email already use" });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = await userModel.create({
      full_name,
      email,
      password: hash,
    });

    res.status(200).json({ user, msg: "data saved successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error during registration" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const available = await userModel.findOne({ email });

    if (!available) {
      return res.status(404).json({ message: "user not found" });
    }

    const isMatch = await bcrypt.compare(password, available.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid Password" });
    }

    const payload = { id: available._id, email: available.email };
    const token = jwt.sign(payload, Secret_key, { expiresIn: "24h" });

    // Cookie Security Fix for Railway/Vercel
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: true,   // Railway par HTTPS hota hai, isliye true hi rahega
      sameSite: "none",
      partitioned: true, // Naya Chrome rule for cross-site cookies
      path: "/",
      maxAge: 24 * 60 * 60 * 1000 // 1 din ki validity
    });

    res.status(200).json({
      message: "user login success",
      email,
      full_name: available.full_name,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// --- Property & Other Routes (Keep as they are) ---

app.get("/property/detail", async (req, res) => {
  try {
    const data = await propertyModel.find().sort({ availableDate: -1 });
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ msg: "Failed to fetch properties" });
  }
});

app.post("/addProperty", upload.array("images", 5), async (req, res) => {
  try {
    const { Name, Desc, Bathroom, Rooms, type, Area, buy_price, rent_price_3_months, rent_price_6_months, rent_price_annual, Location } = req.body;
    const images = req.files.map((file) => ({
      name: file.originalname,
      data: file.buffer.toString("base64"),
    }));

    const property = await propertyModel.create({
      Name, Desc, Bathroom: Number(Bathroom), Rooms: Number(Rooms), type, Area: Number(Area),
      buy_price: Number(buy_price), rent_price_3_months: Number(rent_price_3_months),
      rent_price_6_months: Number(rent_price_6_months), rent_price_annual: Number(rent_price_annual),
      Location, images,
    });
    res.status(200).json({ msg: "Property added successfully", property });
  } catch (error) {
    res.status(500).json({ msg: "Failed to add property" });
  }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ msg: "Not authenticated" });

  jwt.verify(token, Secret_key, (err, decoded) => {
    if (err) return res.status(403).json({ msg: "Token is invalid" });
    req.user = decoded;
    next();
  });
};

// --- Restored Missing Routes ---

// Contact Form (Post Message)
app.post("/message", async (req, res) => {
  try {
    // Schema has: email, firstName, lastName, phone, message, inquiryType, hearAbout, isRead, date
    const { firstName, lastName, email, phone, message, inquiryType, hearAbout } = req.body;
    await postMessgeModel.create({
      firstName, lastName, email, phone, message, inquiryType, hearAbout
    });
    res.status(200).json({ msg: "Message sent successfully" });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ msg: "Failed to send message" });
  }
});

// Client Need Form (Properties Page)
app.post("/client-need", async (req, res) => {
  try {
    // Schema has: firstName, lastName, email, phone, preferredLocation, propertyType, noOfBathrooms, noOfBedrooms, budget, contactMethod, message
    await clientNeedModel.create(req.body);
    res.status(200).json({ msg: "Request received" });
  } catch (error) {
    console.error("Error submitting client need:", error);
    res.status(500).json({ msg: "Failed to submit request" });
  }
});

// Property Request Form (Detailed Page)
app.post("/requestProperty", async (req, res) => {
  try {
    // Schema has: firstName, lastName, email, phone, purchaseType, rentDuration, message, propertyId, propertyTitle, userId, status
    await propertyRequestModel.create(req.body);
    res.status(200).json({ msg: "Request sent" });
  } catch (error) {
    console.error("Error requesting property:", error);
    res.status(500).json({ msg: "Failed to request property" });
  }
});

// Railway Port Fix
const PORT = process.env.PORT || 2000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});