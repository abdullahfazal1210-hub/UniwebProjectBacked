import mongoose from "mongoose";

const propertyRequestSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    phone: String,
    purchaseType: String,
    rentDuration: String,
    message: String,
    propertyId: String,
    propertyTitle: String,
    userId: String,
    status: {
        type: String, 
        default: "Pending",
    },
    isRead: {
        type: Boolean,
        default: false,
    },
    date: {
        type: Date,
        default: Date.now,
    },
});

const propertyRequestModel = mongoose.model(
    "propertyRequest",
    propertyRequestSchema
);
export default propertyRequestModel;
