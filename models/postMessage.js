import mongoose, { Types } from "mongoose";

const postMessageSchema = mongoose.Schema({
  email: String,
  firstName: String,
  lastName: String,
  phone: String,
  message: String,
  inquiryType: String,
  hearAbout: String,
  isRead: {
    type: Boolean,
    default: false,
  },
  date: {
    type: Date,
    default: Date.now
  }




})

const postMessgeModel = mongoose.model("postMessage", postMessageSchema)
export default postMessgeModel;