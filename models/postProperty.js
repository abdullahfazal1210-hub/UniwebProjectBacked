import mongoose from "mongoose";

const ImageSchema = new mongoose.Schema({
  name: String,
  data: String, // base64 
});

const PropertySchema = new mongoose.Schema({
  Name: String,
  Desc: String,
  Bathroom: Number,
  Rooms: Number,
  type: String,
  Area: Number,

  buy_price: Number,
  rent_price_3_months: Number,
  rent_price_6_months: Number,
  rent_price_annual: Number,

  Location: String,
  images: [ImageSchema],

  
  availabilityStatus: {
    type: String,
    default: "Available" 
  },
  availableDate: Date,
  rentDuration: String,
});

const propertyModel = mongoose.model("property", PropertySchema);
export default propertyModel;
