import mongoose from "mongoose";



const userSchema = mongoose.Schema({

    full_name: String,
    email: String,
    password: String,
    googleId: String,
    profileImage: String,
    Date: {
        type: Date,
        default: Date.now
    },
    post: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "post"
    }

})

const userModel = mongoose.model("user", userSchema)
export default userModel;