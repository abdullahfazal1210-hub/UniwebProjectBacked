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

mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log("Connected to MongoDB");
}).catch((err) => {
  console.log("Error connecting to MongoDB", err);
});

const app = express();

app.use(compression());
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "*", // Allow all origins for production (or specifiy your frontend domain)
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

const upload = multer({ storage: multer.memoryStorage() });
const Secret_key = process.env.JWT_SECRET || "abdullah123@!";

app.post("/register", async (req, res) => {
  const { full_name, email, password } = req.body;
  console.log(full_name, password, email);

  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(password, salt, async function (err, hash) {
      try {
        const check = await userModel.findOne({ email });
        console.log(check);

        if (!check) {
          const user = await userModel.create({
            full_name,
            email,
            password: hash,
          });
          console.log("user creaed successfully");

          res.status(200).json({
            user,
            msg: "data saved succesfully",
          });
        } else {
          console.log("email already use");

          res.status(500).json({
            message: "email already use",
          });
        }
      } catch (error) {
        console.log(error);
      }
    });
  });
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const avalible = await userModel.findOne({ email });

    if (avalible) {
      bcrypt.compare(password, avalible.password, function (err, result) {
        console.log("password match", result);
        if (result) {
          const payload = {
            id: avalible._id,
            email: avalible.email,
          };

          const token = jwt.sign(payload, Secret_key, { expiresIn: "1h" });

          res.cookie("authToken", token, {
            httpOnly: false,
            secure: false,
            sameSite: "lax",
            path: "/",
          });

          res.status(200).json({
            message: "user login success",
            email,
            full_name: avalible.full_name,
          });
        } else {
          res.status(401).json({
            message: "Invalid Password",
          });
        }
      });
    } else {
      res.status(404).json({
        message: "user not found",
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "server error",
    });
  }
});

app.get("/auth/google", async (req, res) => {
  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const url = await google.createAuthorizationURL(state, codeVerifier, ["profile", "email"]);
  res.cookie("google_oauth_state", state, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/",
    maxAge: 600 * 1000,
  });
  res.cookie("google_oauth_code_verifier", codeVerifier, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/",
    maxAge: 600 * 1000,
  });
  res.redirect(url.toString());
});

app.get("/auth/google/callback", async (req, res) => {
  const { code, state } = req.query;
  const storedState = req.cookies.google_oauth_state;
  const codeVerifier = req.cookies.google_oauth_code_verifier;

  if (!code || !state || state !== storedState || !codeVerifier) {
    return res.status(400).send("Invalid state, code, or code verifier");
  }

  try {
    const tokens = await google.validateAuthorizationCode(code, codeVerifier);
    const accessToken = tokens.accessToken();

    const userResponse = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const googleUser = userResponse.data;

    let user = await userModel.findOne({ googleId: googleUser.sub });
    if (!user) {
      user = await userModel.findOne({ email: googleUser.email });
      if (user) {
        user.googleId = googleUser.sub;
        user.profileImage = googleUser.picture;
        await user.save();
      } else {
        user = await userModel.create({
          full_name: googleUser.name,
          email: googleUser.email,
          googleId: googleUser.sub,
          profileImage: googleUser.picture
        });
      }
    }

    const payload = { id: user._id, email: user.email };
    const token = jwt.sign(payload, Secret_key, { expiresIn: "24h" });

    res.cookie("authToken", token, {
      httpOnly: false,
      secure: false,
      sameSite: "lax",
      path: "/",
    });

    res.redirect(`${process.env.FRONTEND_URL}?name=${encodeURIComponent(user.full_name)}&image=${encodeURIComponent(user.profileImage || "")}&login=success`);
  } catch (error) {
    console.error("Auth error:", error);
    res.status(500).send("Authentication failed");
  }
});

app.post("/addProperty", upload.array("images", 5), async (req, res) => {
  try {
    const {
      Name,
      Desc,
      Bathroom,
      Rooms,
      type,
      Area,
      buy_price,
      rent_price_3_months,
      rent_price_6_months,
      rent_price_annual,
      Location,
    } = req.body;

    console.log(
      buy_price,
      rent_price_3_months,
      rent_price_6_months,
      rent_price_annual
    );

    const images = req.files.map((file) => ({
      name: file.originalname,
      data: file.buffer.toString("base64"),
    }));

    const property = await propertyModel.create({
      Name,
      Desc,
      Bathroom: Number(Bathroom),
      Rooms: Number(Rooms),
      type,
      Area: Number(Area),

      buy_price: Number(buy_price),
      rent_price_3_months: Number(rent_price_3_months),
      rent_price_6_months: Number(rent_price_6_months),
      rent_price_annual: Number(rent_price_annual),

      Location,
      images,
    });

    res.status(200).json({
      msg: "Property added successfully",
      property,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      msg: "Failed to add property",
    });
  }
});

app.get("/property/detail", async (req, res) => {
  try {
    const data = await propertyModel.find().sort({ availableDate: -1 }); // Sorted by date
    res.status(200).json(data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to fetch properties" });
  }
});

app.post("/property/delete", async (req, res) => {
  try {
    const { id } = req.body;
    console.log("Deleting property with ID:", id);

    if (!id) {
      return res.status(400).json({ msg: "Property ID is required" });
    }

    const deleted = await propertyModel.findByIdAndDelete(id.trim());

    if (!deleted) {
      console.log("Property not found for deletion:", id);
      return res.status(404).json({ msg: "Property not found for deletion" });
    }

    console.log("Property deleted successfully");
    res.status(200).json({ msg: "Property deleted success" });
  } catch (error) {
    console.error("Error in POST /property/delete:", error);
    res.status(500).json({ msg: "Failed to delete property", error: error.message });
  }
});

app.post("/property/update", upload.array("images", 5), async (req, res) => {
  try {
    const { id } = req.body;
    console.log("Updating property ID:", id);
    console.log("Request body:", req.body);

    const updateData = { ...req.body };

    // Helper to safely convert to number or null
    const toNum = (val) => {
      if (val === "" || val === null || val === undefined || val === "null" || val === "undefined") return undefined;
      const n = Number(val);
      return isNaN(n) ? undefined : n;
    };

    updateData.Bathroom = toNum(updateData.Bathroom);
    updateData.Rooms = toNum(updateData.Rooms);
    updateData.Area = toNum(updateData.Area);
    updateData.buy_price = toNum(updateData.buy_price);
    updateData.rent_price_3_months = toNum(updateData.rent_price_3_months);
    updateData.rent_price_6_months = toNum(updateData.rent_price_6_months);
    updateData.rent_price_annual = toNum(updateData.rent_price_annual);

    // Remove undefined fields so they don't overwrite with null if not intended
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    // Handle images if new ones are uploaded
    if (req.files && req.files.length > 0) {
      console.log("New images uploaded:", req.files.length);
      const newImages = req.files.map((file) => ({
        name: file.originalname,
        data: file.buffer.toString("base64"),
      }));
      updateData.images = newImages;
    }

    const updatedProperty = await propertyModel.findByIdAndUpdate(id.trim(), updateData, { new: true });

    if (!updatedProperty) {
      console.log("Property not found with ID:", id);
      return res.status(404).json({ msg: "Property not found in database" });
    }

    console.log("Property updated successfully");
    res.status(200).json({ msg: "Property updated successfully", property: updatedProperty });
  } catch (error) {
    console.error("Error in POST /property/update:", error);
    res.status(500).json({ msg: "Failed to update property", error: error.message });
  }
});


app.get("/getmessage", async (req, res) => {
  try {
    const messages = await postMessgeModel.find().sort({ date: -1 });
    res.status(200).json({
      data: messages,
      msg: "success",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Server error" });
  }
});

app.post("/message", async (req, res) => {
  try {
    const { firstName, lastName, email, phone, message, inquiryType, hearAbout } = req.body;

    const newMessage = await postMessgeModel.create({
      firstName,
      lastName,
      email,
      phone,
      message,
      inquiryType,
      hearAbout
    });

    res.status(200).json({
      msg: "Message sent successfully",
      data: newMessage
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to send message" });
  }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ msg: "Not authenticated" });

  jwt.verify(token, Secret_key, (err, decoded) => {
    if (err) return res.status(403).json({ msg: "Token is invalid" });
    req.user = decoded; // Attach user info
    next();
  });
};

// -- Client Needs API --
app.post("/client-need", verifyToken, async (req, res) => {
  try {
    const data = req.body;
    const newNeed = await clientNeedModel.create(data);
    res.status(200).json({ msg: "Client Need submitted", data: newNeed });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to submit client need" });
  }
});

app.get("/client-need", async (req, res) => {
  try {
    const needs = await clientNeedModel.find().sort({ date: -1 });
    res.status(200).json({ data: needs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to fetch client needs" });
  }
});


// -- Property Requests API --

app.post("/requestProperty", verifyToken, async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      purchaseType,
      rentDuration,
      message,
      propertyId,
      propertyTitle,
    } = req.body;

    const newRequest = await propertyRequestModel.create({
      firstName,
      lastName,
      email,
      phone,
      purchaseType,
      rentDuration,
      message,
      propertyId,
      propertyTitle,
      userId: req.user.id,
    });

    res.status(200).json({
      msg: "Request submitted successfully",
      data: newRequest,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to submit request" });
  }
});

app.get("/propertyRequests", async (req, res) => {
  try {
    const requests = await propertyRequestModel.find().sort({ date: -1 });
    res.status(200).json(requests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to fetch requests" });
  }
});

app.put("/propertyRequest/:id", async (req, res) => {
  try {
    const { status } = req.body;
    const { id } = req.params;

    const updated = await propertyRequestModel.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    // If request is Accepted, update the main Property status
    if (status === "Accepted" && updated) {
      let availabilityStatus = "Available";
      let availableDate = null;

      if (updated.purchaseType === "buy") {
        availabilityStatus = "Sold";
        availableDate = new Date(); // Record Sale Date for Graph
      } else if (updated.purchaseType === "rent") {
        availabilityStatus = "Rented";
        // Calculate Available Date based on duration
        const duration = parseInt(updated.rentDuration); // 3, 6, or 12
        if (!isNaN(duration)) {
          const date = new Date();
          date.setMonth(date.getMonth() + duration);
          availableDate = date;
        }
      }

      await propertyModel.findByIdAndUpdate(updated.propertyId, {
        availabilityStatus,
        rentDuration: updated.rentDuration,
        availableDate
      });
    }

    res.status(200).json(updated);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to update status" });
  }
});

app.get("/property/status/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Check for Accepted requests first (Occupied)
    const acceptedRequest = await propertyRequestModel.findOne({
      propertyId: id,
      status: "Accepted"
    });

    if (acceptedRequest) {
      return res.status(200).json({
        status: "Occupied",
        type: acceptedRequest.purchaseType,
        duration: acceptedRequest.rentDuration
      });
    }

    // Check for Pending requests
    const pendingRequests = await propertyRequestModel.find({
      propertyId: id,
      status: "Pending"
    });

    if (pendingRequests.length > 0) {
      return res.status(200).json({
        status: "Pending",
        count: pendingRequests.length
      });
    }

    return res.status(200).json({ status: "Available" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to fetch status" });
  }
});

// -- Dashboard Stats API --
// -- Notifications API --
app.get("/notifications/counts", async (req, res) => {
  try {
    const [messages, clientNeeds, propertyRequests] = await Promise.all([
      postMessgeModel.countDocuments({ isRead: false }),
      clientNeedModel.countDocuments({ isRead: false }),
      propertyRequestModel.countDocuments({ isRead: false })
    ]);

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

app.put("/notifications/mark-read/:type", async (req, res) => {
  try {
    const { type } = req.params;
    let model;

    switch (type) {
      case "message":
        model = postMessgeModel;
        break;
      case "client-need":
        model = clientNeedModel;
        break;
      case "property-req":
        model = propertyRequestModel;
        break;
      default:
        return res.status(400).json({ msg: "Invalid type" });
    }

    // Update all unread documents of this type to read
    await model.updateMany({ isRead: false }, { isRead: true });

    res.status(200).json({ msg: "Marked as read" });
  } catch (error) {
    console.error("Error marking read:", error);
    res.status(500).json({ msg: "Failed to mark as read" });
  }
});

app.get("/dashboard-stats", async (req, res) => {
  try {
    const [totalUsers, totalSold, totalMessages, salesTrend, rentalTrend, userTrend] = await Promise.all([
      userModel.countDocuments(),
      propertyModel.countDocuments({ availabilityStatus: "Sold" }),
      postMessgeModel.countDocuments(),
      propertyModel.aggregate([
        { $match: { availabilityStatus: "Sold", availableDate: { $ne: null } } },
        {
          $group: {
            _id: { $month: "$availableDate" },
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id": 1 } }
      ]),
      propertyModel.aggregate([
        { $match: { availabilityStatus: "Rented", availableDate: { $ne: null } } },
        {
          $group: {
            _id: { $month: "$availableDate" },
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id": 1 } }
      ]),
      userModel.aggregate([
        {
          $group: {
            _id: { $month: "$Date" }, // Using "Date" field from schema
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id": 1 } }
      ])
    ]);

    res.status(200).json({
      totalUsers,
      totalSold,
      totalMessages,
      salesTrend,
      rentalTrend,
      userTrend
    });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    res.status(500).json({ msg: "Failed to fetch stats" });
  }
});

app.get("/allusers", async (req, res) => {
  try {
    const users = await userModel.find().select("-password").sort({ Date: -1 });
    res.status(200).json({ data: users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ msg: "Failed to fetch users" });
  }
});

// -- User History API --
app.get("/user/history", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    // Find requests made by this user that were accepted (bought or rented)
    const history = await propertyRequestModel.find({
      userId: userId,
      status: "Accepted"
    }).sort({ date: -1 });

    // Fetch the full property details to show images
    const propertyIds = history.map(h => h.propertyId);
    const properties = await propertyModel.find({ _id: { $in: propertyIds } });

    // Merge data
    const result = history.map(h => {
      const prop = properties.find(p => p._id.toString() === h.propertyId);
      return {
        ...h._doc,
        image: prop && prop.images && prop.images.length > 0 ? prop.images[0] : null,
        propertyDetails: prop
      };
    });

    res.status(200).json({
      msg: "History fetched",
      data: result
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to fetch history" });
  }
});

app.get("/admin/user-history/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    // Find requests made by this specific user that were accepted (bought or rented)
    const history = await propertyRequestModel.find({
      userId: userId,
      status: "Accepted"
    }).sort({ date: -1 });

    // Fetch the full property details to show images
    const propertyIds = history.map(h => h.propertyId);
    const properties = await propertyModel.find({ _id: { $in: propertyIds } });

    // Merge data
    const result = history.map(h => {
      const prop = properties.find(p => p._id.toString() === h.propertyId);
      return {
        ...h._doc,
        image: prop && prop.images && prop.images.length > 0 ? prop.images[0] : null,
        propertyDetails: prop
      };
    });

    res.status(200).json({
      data: result
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Failed to fetch user history" });
  }
});

const PORT = process.env.PORT || 2000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
