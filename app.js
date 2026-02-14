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
import nodemailer from "nodemailer";

dotenv.config();

// Temporary in-memory OTP storage
const otpStore = new Map();

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
    // 1. Changed https to http for localhost
    // 2. Added your production URL so both work
    origin: ["http://localhost:3000", "https://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

const upload = multer({ storage: multer.memoryStorage() });
const Secret_key = process.env.JWT_SECRET || "abdullah123@!";

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ message: "Not authenticated" });

  jwt.verify(token, Secret_key, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Token is invalid" });
    req.user = decoded;
    next();
  });
};

// --- Test Route ---
app.get("/test", (req, res) => {
  res.status(200).json({ message: "Backend is running and reachable!" });
});

// --- OTP Verification Logic ---

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "abdullah.fazal1210@gmail.com",
    pass: "rboxsyvyvwuifmcj", // App Password without spaces
  },
});

// --- FORGOT PASSWORD ROUTES ---

app.post("/forgot-password-send-otp", async (req, res) => {
  console.log("📨 Received request for /forgot-password-send-otp for CNIC:", req.body.cnic);
  try {
    const { cnic } = req.body;
    if (!cnic) return res.status(400).json({ message: "CNIC is required" });

    // FLEXIBLE SEARCH: Try exact match first, then try without hyphens
    let user = await userModel.findOne({ cnic });

    if (!user) {
      console.log("🔍 Exact match not found, trying normalized search...");
      const cleanCnic = cnic.replace(/\D/g, "");
      // We search where cnic cleaned of any non-digits matches our clean input
      // This is a bit slow in Mongo but reliable for debugging
      const allUsers = await userModel.find({});
      user = allUsers.find(u => {
        const storedClean = (u.cnic || "").replace(/\D/g, "");
        return storedClean === cleanCnic;
      });
    }

    if (!user) {
      console.log(`❌ Forgot Password failed: CNIC ${cnic} not found in DB`);
      return res.status(404).json({ message: "No account found with this CNIC." });
    }

    const email = user.email;
    if (!email) {
      console.log("❌ Error: Found user but they have NO email address in DB.");
      return res.status(400).json({ message: "No email address associated with this CNIC. Please contact support." });
    }

    console.log(`🔍 User found! Email: ${email}`);
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 60000; // 1 minute expiry

    console.log(`🔢 Generated Reset OTP: ${otp} for ${email}`);
    otpStore.set(email, { otp, expiry });

    const mailOptions = {
      from: `"Talha Builders Support" <abdullah.fazal1210@gmail.com>`,
      to: email,
      subject: `[Talha Builders] Password Reset Code: ${otp}`,
      text: `Your One-Time Password (OTP) for password reset is: ${otp}. This code will expire in 1 minute.`,
      html: `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0; border-radius: 12px; overflow: hidden; background-color: #ffffff;">
          <div style="background-color: #d11a2a; padding: 30px; text-align: center;">
            <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">TALHA BUILDERS</h1>
          </div>
          <div style="padding: 40px; color: #333333;">
            <h2 style="color: #1A1A1A; margin-top: 0;">Password Reset Verification</h2>
            <p style="font-size: 16px; line-height: 1.6; color: #666666;">
              We received a request to reset your password. Please use the verification code below to proceed.
            </p>
            <div style="text-align: center; margin: 40px 0;">
              <div style="display: inline-block; background-color: #f4f4f4; padding: 20px 40px; border-radius: 12px; font-size: 36px; font-weight: bold; color: #d11a2a; letter-spacing: 10px; border: 2px dashed #d11a2a;">
                ${otp}
              </div>
            </div>
            <p style="font-size: 14px; color: #999999; text-align: center;">
              This code is valid for <strong>1 minute</strong>.
            </p>
            <hr style="border: 0; border-top: 1px solid #eeeeee; margin: 30px 0;" />
            <p style="font-size: 12px; color: #aaaaaa; line-height: 1.5;">
              If you didn't request this, please secure your account.
            </p>
          </div>
          <div style="background-color: #fafafa; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
            <p style="margin: 0; font-size: 12px; color: #999999;">&copy; 2026 Talha Builders. All rights reserved.</p>
          </div>
        </div>
      `,
    };

    console.log("📤 Sending Reset OTP email...");
    await transporter.sendMail(mailOptions);
    console.log("✅ Reset OTP email sent successfully to:", email);

    res.status(200).json({ message: "OTP sent to your registered email", email });
  } catch (error) {
    console.error("❌ ERROR sending reset OTP:", error);
    res.status(500).json({ message: "Failed to send reset OTP", error: error.message });
  }
});

app.post("/reset-password", async (req, res) => {
  console.log("🔐 Received request for /reset-password for:", req.body.email);
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and new password are required" });

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    // Update user password
    const user = await userModel.findOneAndUpdate({ email }, { password: hash }, { new: true });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    console.log("✅ Password updated successfully for:", email);
    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("❌ ERROR resetting password:", error);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// --- END FORGOT PASSWORD ROUTES ---

app.post("/send-otp", async (req, res) => {
  console.log("📨 Received request for /send-otp to:", req.body.email);
  try {
    const { email, cnic } = req.body;
    if (!email) {
      console.log("❌ Error: Email is missing in request body");
      return res.status(400).json({ message: "Email is required" });
    }

    // Check if email or CNIC already exists BEFORE sending OTP
    const checkEmail = await userModel.findOne({ email });
    if (checkEmail) {
      console.log(`❌ Registration failed: Email ${email} already in use`);
      return res.status(400).json({ message: "Email already in use" });
    }

    if (cnic) {
      const checkCnic = await userModel.findOne({ cnic });
      if (checkCnic) {
        console.log(`❌ Registration failed: CNIC ${cnic} already registered`);
        return res.status(400).json({ message: "CNIC already registered" });
      }
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 60000; // 1 minute expiry

    console.log(`🔢 Generated OTP: ${otp} for ${email}`);
    otpStore.set(email, { otp, expiry });

    const mailOptions = {
      from: `"Talha Builders Support" <abdullah.fazal1210@gmail.com>`,
      to: email,
      subject: `[Talha Builders] Your Verification Code: ${otp}`,
      text: `Your One-Time Password (OTP) for registration is: ${otp}. This code will expire in 1 minute.`,
      html: `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0; border-radius: 12px; overflow: hidden; background-color: #ffffff;">
          <div style="background-color: #703BF7; padding: 30px; text-align: center;">
            <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">TALHA BUILDERS</h1>
          </div>
          <div style="padding: 40px; color: #333333;">
            <h2 style="color: #1A1A1A; margin-top: 0;">Email Verification</h2>
            <p style="font-size: 16px; line-height: 1.6; color: #666666;">
              Thank you for choosing Talha Builders. Please use the verification code below to complete your registration process.
            </p>
            <div style="text-align: center; margin: 40px 0;">
              <div style="display: inline-block; background-color: #f4f4f4; padding: 20px 40px; border-radius: 12px; font-size: 36px; font-weight: bold; color: #703BF7; letter-spacing: 10px; border: 2px dashed #703BF7;">
                ${otp}
              </div>
            </div>
            <p style="font-size: 14px; color: #999999; text-align: center;">
              This code is valid for <strong>1 minute</strong>.
            </p>
            <hr style="border: 0; border-top: 1px solid #eeeeee; margin: 30px 0;" />
            <p style="font-size: 12px; color: #aaaaaa; line-height: 1.5;">
              If you didn't request this email, you can safely ignore it. Someone might have typed your email address by mistake.
            </p>
          </div>
          <div style="background-color: #fafafa; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
            <p style="margin: 0; font-size: 12px; color: #999999;">&copy; 2026 Talha Builders. All rights reserved.</p>
          </div>
        </div>
      `,
    };

    console.log("📤 Attempting to send email via Nodemailer...");
    const info = await transporter.sendMail(mailOptions);
    console.log("✅ Email sent successfully! MessageId:", info.messageId);

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("❌ NODEMAILER ERROR:", error);
    res.status(500).json({
      message: "Failed to send OTP",
      error: error.message,
      details: error.code || "No code"
    });
  }
});

app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const storedData = otpStore.get(email);

  if (!storedData) {
    return res.status(400).json({ message: "OTP not requested or expired" });
  }

  if (Date.now() > storedData.expiry) {
    otpStore.delete(email);
    return res.status(400).json({ message: "OTP expired" });
  }

  if (storedData.otp === otp) {
    otpStore.delete(email);
    res.status(200).json({ message: "OTP verified successfully" });
  } else {
    res.status(400).json({ message: "Invalid OTP" });
  }
});

// --- Auth Routes Optimized ---

app.post("/register", async (req, res) => {
  console.log("📝 Final Registration Request Body:", req.body);
  try {
    const { full_name, email, password, cnic, father_name, address, mobile } = req.body;

    // Final check before creation - only check if values are truthy
    const query = [];
    if (email) query.push({ email });
    if (cnic) query.push({ cnic });

    if (query.length > 0) {
      const existingUser = await userModel.findOne({ $or: query });
      if (existingUser) {
        console.log("❌ Registration Blocked: User already exists.");
        const reason = existingUser.email === email ? "Email" : "CNIC";
        console.log(`🔍 Conflict found on: ${reason}`);
        return res.status(400).json({ message: `${reason} already registered. Please check your data.` });
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = await userModel.create({
      full_name,
      email,
      password: hash,
      cnic,
      father_name,
      address,
      mobile,
    });

    res.status(200).json({ user, msg: "Data saved successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error during registration" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { cnic, password } = req.body;
    const available = await userModel.findOne({ cnic });

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
      email: available.email,
      full_name: available.full_name,
      profileImage: available.profileImage, // Include profile image in login response
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// Change Password Route (Authenticated)
app.post("/change-password", verifyToken, async (req, res) => {
  console.log("🔐 Authenticated request for /change-password from:", req.user.email);
  try {
    const { oldPassword, newPassword } = req.body;
    const { id } = req.user;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ message: "Old and new passwords are required" });
    }

    // Find user
    const user = await userModel.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verify old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect old password" });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newPassword, salt);

    // Update password
    user.password = hash;
    await user.save();

    console.log("✅ Password updated successfully for:", user.email);
    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("❌ ERROR changing password:", error);
    res.status(500).json({ message: "Failed to change password" });
  }
});

// Logout Route (Clear Cookie)
app.post("/logout", (req, res) => {
  res.clearCookie("authToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    partitioned: true, // Match creation options
    path: "/"
  });
  res.status(200).json({ msg: "Logged out successfully" });
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
        userId = decoded.id; // Extract ID from token
        userEmail = decoded.email;
      } catch (err) {
        console.warn("Invalid token during property request:", err.message);
      }
    }

    // Schema has: firstName, lastName, email, phone, purchaseType, rentDuration, message, propertyId, propertyTitle, userId, status
    await propertyRequestModel.create({
      ...req.body,
      userId: userId ? userId.toString() : null, // Ensure string or null
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
    const { id, email } = req.user;

    // Strict check to ensure we don't query with undefined
    if (!id) {
      return res.status(400).json({ msg: "User ID missing" });
    }

    // Match by UserID OR Email (for robustness with older data or manual email entry)
    const history = await propertyRequestModel.find({
      $or: [
        { userId: id },
        { email: email }
      ]
    }).sort({ date: -1 });

    res.status(200).json({ data: history });
  } catch (error) {
    console.error("Error fetching my history:", error);
    res.status(500).json({ msg: "Failed to fetch history" });
  }
});

// Get User Profile Details
app.get("/user/profile", verifyToken, async (req, res) => {
  try {
    const { id } = req.user;
    const user = await userModel.findById(id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ message: "Server error fetching profile" });
  }
});

// Update User Profile Details
app.put("/user/profile", verifyToken, async (req, res) => {
  try {
    const { id } = req.user;
    const { full_name, email, cnic, father_name, address, mobile } = req.body;

    const updatedUser = await userModel.findByIdAndUpdate(
      id,
      { full_name, email, cnic, father_name, address, mobile },
      { new: true }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "Profile updated successfully", user: updatedUser });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ message: "Server error updating profile" });
  }
});

// Update Profile Photo
app.post("/user/update-photo", verifyToken, upload.single("profileImage"), async (req, res) => {
  try {
    const { id } = req.user;
    if (!req.file) {
      return res.status(400).json({ message: "No image provided" });
    }

    // Convert buffer to base64
    const base64Image = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;

    const updatedUser = await userModel.findByIdAndUpdate(
      id,
      { profileImage: base64Image },
      { new: true }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "Photo updated successfully",
      profileImage: base64Image,
      user: updatedUser
    });
  } catch (error) {
    console.error("Error updating photo:", error);
    res.status(500).json({ message: "Server error updating photo" });
  }
});

// Get Single Request Details (For Invoice)
app.get("/user/request/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Find request and ensure it belongs to the user
    const request = await propertyRequestModel.findOne({ _id: id, userId: userId });

    if (!request) {
      return res.status(404).json({ msg: "Request not found or unauthorized" });
    }

    // Fetch associated property details to get price info
    const property = await propertyModel.findById(request.propertyId);

    res.status(200).json({
      request,
      property
    });
  } catch (error) {
    console.error("Error fetching request details:", error);
    res.status(500).json({ msg: "Failed to fetch details" });
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
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});