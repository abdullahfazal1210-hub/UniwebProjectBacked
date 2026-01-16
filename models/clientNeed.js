import mongoose from "mongoose";

const clientNeedSchema = mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    phone: String,
    preferredLocation: String,
    propertyType: String,
    noOfBathrooms: String,
    noOfBedrooms: String,
    budget: String,
    contactMethod: [String], 
    message: String,
    isRead: {
        type: Boolean,
        default: false,
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const clientNeedModel = mongoose.model("clientNeed", clientNeedSchema);
export default clientNeedModel;
