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

// Add Property
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

// Get Property Status (For Detailed Page)
app.get("/property/status/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const property = await propertyModel.findById(id);

    if (!property) return res.status(404).json({ msg: "Property not found" });

    // Count pending requests
    const pendingCount = await propertyRequestModel.countDocuments({
      propertyId: id,
      status: "Pending"
    });

    res.status(200).json({
      status: property.availabilityStatus || "Available",
      count: pendingCount,
      duration: property.rentDuration || 0,
      availableDate: property.availableDate
    });
  } catch (error) {
    console.error("Error fetching property status:", error);
    res.status(500).json({ msg: "Failed to fetch status" });
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
// Property Request Form (Detailed Page)
app.post("/requestProperty", async (req, res) => {
  try {
    const token = req.cookies.authToken;
    let userId = null;
    let userEmail = null;

    if (token) {
      try {
        const decoded = jwt.verify(token, Secret_key);
        userId = decoded.id;
        userEmail = decoded.email;
      } catch (err) {
        console.warn("Invalid token during property request:", err.message);
      }
    }

    // Schema has: firstName, lastName, email, phone, purchaseType, rentDuration, message, propertyId, propertyTitle, userId, status
    await propertyRequestModel.create({
      ...req.body,
      userId: userId, // Attach userId if authenticated
      email: userEmail || req.body.email // Prefer token email, fallback to form email
    });
    res.status(200).json({ msg: "Request sent" });
  } catch (error) {
    console.error("Error requesting property:", error);
    res.status(500).json({ msg: "Failed to request property" });
  }
});

// --- Admin Dashboard Routes ---

// Dashboard Stats
app.get("/dashboard-stats", async (req, res) => {
  try {
    const totalUsers = await userModel.countDocuments();
    const totalSold = await propertyRequestModel.countDocuments({ status: "Accepted" }); // Assuming accepted means sold/rented
    const totalMessages = await postMessgeModel.countDocuments();

    // Simple trends (mock logic or aggregation if needed)
    // For now returning basic counts
    res.status(200).json({
      totalUsers,
      totalSold,
      totalMessages,
      salesTrend: [], // Implement aggregation if needed
      rentalTrend: [],
      userTrend: []
    });
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ msg: "Failed to fetch stats" });
  }
});

// Get All Users
app.get("/allusers", async (req, res) => {
  try {
    const users = await userModel.find().sort({ Date: -1 });
    res.status(200).json({ data: users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ msg: "Failed to fetch users" });
  }
});

// Get User History (Admin)
app.get("/admin/user-history/:id", async (req, res) => {
  try {
    const { id } = req.params;
    // Find requests by this user (assuming email or internal ID match. Schema has userId)
    // First find the user to get their email if needed, or just search by userId match
    const user = await userModel.findById(id);
    if (!user) return res.status(404).json({ msg: "User not found" });

    // Assuming we link by email or userId. Let's try matching both to be safe or just email if userId wasn't stored consistently
    const history = await propertyRequestModel.find({
      $or: [{ userId: id }, { email: user.email }]
    }).sort({ date: -1 });

    res.status(200).json({ data: history });
  } catch (error) {
    console.error("Error fetching user history:", error);
    res.status(500).json({ msg: "Failed to fetch history" });
  }
});

// Get My History (User)
app.get("/user/history", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const history = await propertyRequestModel.find({ userId: userId }).sort({ date: -1 });
    res.status(200).json({ data: history });
  } catch (error) {
    console.error("Error fetching my history:", error);
    res.status(500).json({ msg: "Failed to fetch history" });
  }
});

// Get Messages (Contact Form)
app.get("/getmessage", async (req, res) => {
  try {
    const messages = await postMessgeModel.find().sort({ date: -1 });
    res.status(200).json({ data: messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ msg: "Failed to fetch messages" });
  }
});

// Get Client Needs
app.get("/client-need", async (req, res) => {
  try {
    const needs = await clientNeedModel.find().sort({ date: -1 });
    res.status(200).json({ data: needs });
  } catch (error) {
    console.error("Error fetching client needs:", error);
    res.status(500).json({ msg: "Failed to fetch client needs" });
  }
});

// Get Property Requests
app.get("/propertyRequests", async (req, res) => {
  try {
    const requests = await propertyRequestModel.find().sort({ date: -1 });
    res.status(200).json(requests);
  } catch (error) {
    console.error("Error fetching property requests:", error);
    res.status(500).json({ msg: "Failed to fetch requests" });
  }
});

// Update Property Request Status and Property Availability
app.put("/propertyRequest/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    // 1. Update the Request Status
    const request = await propertyRequestModel.findByIdAndUpdate(id, { status }, { new: true });

    // 2. If Accepted, Update the Property Status
    if (status === "Accepted" && request) {
      const propertyId = request.propertyId;

      if (request.purchaseType === "buy") {
        // Mark as Sold
        await propertyModel.findByIdAndUpdate(propertyId, {
          availabilityStatus: "Sold"
        });
      } else if (request.purchaseType === "rent") {
        // Mark as Occupied and calculate return date
        const durationMonths = parseInt(request.rentDuration) || 0;
        const availableDate = new Date();
        availableDate.setMonth(availableDate.getMonth() + durationMonths);

        await propertyModel.findByIdAndUpdate(propertyId, {
          availabilityStatus: "Occupied",
          rentDuration: request.rentDuration,
          availableDate: availableDate
        });
      }
    }

    res.status(200).json({ msg: "Status updated" });
  } catch (error) {
    console.error("Error updating status:", error);
    res.status(500).json({ msg: "Failed to update status" });
  }
});

// Notification Counts for Sidebar
app.get("/notifications/counts", async (req, res) => {
  try {
    const messages = await postMessgeModel.countDocuments({ isRead: false });
    const clientNeeds = await clientNeedModel.countDocuments({ isRead: false });
    const propertyRequests = await propertyRequestModel.countDocuments({ isRead: false });

    res.status(200).json({
      messages,
      clientNeeds,
      propertyRequests
    });
  } catch (error) {
    console.error("Error fetching notification counts:", error);
    res.status(500).json({ msg: "Failed to fetch counts" });
  }
});

// Mark Notifications Read
app.put("/notifications/mark-read/:type", async (req, res) => {
  try {
    const { type } = req.params;
    if (type === "message") {
      await postMessgeModel.updateMany({ isRead: false }, { isRead: true });
    } else if (type === "property-req") {
      await propertyRequestModel.updateMany({ isRead: false }, { isRead: true });
    } else if (type === "client-need") {
      await clientNeedModel.updateMany({ isRead: false }, { isRead: true });
    }
    res.status(200).json({ msg: "Marked as read" });
  } catch (error) {
    console.error("Error marking read:", error);
    res.status(500).json({ msg: "Failed to mark as read" });
  }
});

// Update Property (Edit)
app.post("/property/update", upload.array("images", 5), async (req, res) => {
  try {
    const { id, Name, Desc, Bathroom, Rooms, type, Area, buy_price, rent_price_3_months, rent_price_6_months, rent_price_annual, Location } = req.body;

    const updateData = {
      Name, Desc, Bathroom: Number(Bathroom), Rooms: Number(Rooms), type, Area: Number(Area),
      buy_price: Number(buy_price), rent_price_3_months: Number(rent_price_3_months),
      rent_price_6_months: Number(rent_price_6_months), rent_price_annual: Number(rent_price_annual),
      Location
    };

    // If new images are uploaded, handle them (simple link logic or replace)
    // For now we assume appending or replacing requires more logic, keeping simple update
    // If you want to replace images:
    if (req.files && req.files.length > 0) {
      updateData.images = req.files.map((file) => ({
        name: file.originalname,
        data: file.buffer.toString("base64"),
      }));
    }

    await propertyModel.findByIdAndUpdate(id, updateData);
    res.status(200).json({ msg: "Property updated successfully" });
  } catch (error) {
    console.error("Error updating property:", error);
    res.status(500).json({ msg: "Failed to update property" });
  }
});

// Delete Property
app.post("/property/delete", async (req, res) => {
  try {
    const { id } = req.body;
    await propertyModel.findByIdAndDelete(id);
    res.status(200).json({ msg: "Property deleted successfully" });
  } catch (error) {
    console.error("Error deleting property:", error);
    res.status(500).json({ msg: "Failed to delete property" });
  }
});

// Railway Port Fix
const PORT = process.env.PORT || 2000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});