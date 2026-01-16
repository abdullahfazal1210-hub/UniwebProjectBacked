import mongoose, { Types } from "mongoose";

const postSchema  =  mongoose.Schema({
    postData : String,
    user: {type : mongoose.Schema.Types.ObjectId,
        ref:"user"
    },
    
    
})

const postModel = mongoose.model("post",postSchema)
export default postModel;