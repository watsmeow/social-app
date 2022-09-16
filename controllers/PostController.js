import PostModel from '../models/PostModel.js';
import UserModel from '../models/UserModel.js';
import mongoose, { mongo } from 'mongoose';

//create new post
export const createPost = async (req, res) => {
    //will send all the details for a new post in the body of the request, as soon as the reqest body is received it's imbedded into the post model and newPost = an object in the post model format
    const newPost = new PostModel(req.body)
    try {
        //save the post in the database
        await newPost.save()
        res.status(200).json({ message: "Post successful!"})
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot create your post."})
    }
};


//get a post
export const getPost = async (req, res) => {
    //gets post id from params of the url
    const id = req.params.id

    try {
        //if post is found by its id, assigns post to 'post' variable
        const post = await PostModel.findById(id)
        res.status(200).json(post)
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot get requested post."})
    }
};

//update a post
export const updatePost = async (req, res) => {
    //gets post id from params of the url
    const id = req.params.id
    //get user id from the body of the request
    const { userId } = req.body

    try {
        //if post is found by its id, assigns post to 'post' variable
        const post = await PostModel.findById(id)
        //make sure that the user requesting the update owns the post
        if (post.userId === userId) {
            //update the post with what is sent in the request body
            await post.updateOne({ $set: req.body })
            res.status(200).json({ message: "Post updated!"})
        } else {
            res.status(403).json({ message: "You can only update your own posts. Duh."}) 
        }
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot update post."})
    }
};

//delete a post
export const deletePost = async (req, res) => {
    //gets post id from params of the url
    const id = req.params.id
    //get user id from the body of the request
    const { userId } = req.body

    try {
        //if post is found by its id, assigns post to 'post' variable
        const post = await PostModel.findById(id)
        //make sure that the user requesting the deletion owns the post
        if (post.userId === userId) {
            //delete the post with what is sent in the request body
            await post.deleteOne()
            res.status(200).json({ message: "Post deleted!"})
        } else {
            res.status(403).json({ message: "You can only delete your own posts. Duh."}) 
        }
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot delete post."})
    }
};

//like or dislike a post
export const likePost = async (req, res) => {
    //gets post id from params of the url
    const id = req.params.id
    //get user id from the body of the request
    const { userId } = req.body

    try {
        const post = await PostModel.findById(id)
        //checking if the user id is already in the likes array and has therefore already liked the post
        if (!post.likes.includes(userId)) {
            await post.updateOne({ $push: {likes: userId}})
            res.status(200).json({ message: "You like this post!"})
        } else {
            await post.updateOne({ $pull: {likes: userId}})
            res.status(200).json({ message: "You unliked this post!"})
        }
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot like post."})
    }
};

//get timeline posts
export const getTimeLinePosts = async (req, res) => {
    //gets post id from params of the url
    const userId = req.params.id


    try {
        //gets the posts of the current user
        const posts = await PostModel.find({ userId: userId })
        const followingPosts = await UserModel.aggregate([
            //do the following steps in order to aggregate
            {
                //match with the user who's id has been sent with the params
                $match: {
                    _id: new mongoose.Types.ObjectId(userId)
                }
            },
            {
                //lookup used when you're using one model to query, but want to get results from another model
                $lookup: {
                    //create an integration pipeline to do the above
                    from: "posts", //I want to integrate with my posts model/posts collection in the DB
                    localField: "following", //the field local to the model you're querying from; we're looking in the following array and seeing if the user ID's match with any posts in the post model
                    foreignField: "userId", //in the posts model this is the field we want to reference to match with the local field
                    as: "followingPosts" //get the results as the following posts object
                }
            }, 
            {
                //return type of the aggregation
                $project: {
                    //only want to return one field, the 'followingPosts' field
                    followingPosts: 1, 
                    //id field of object always returned by default, so setting it to zero to essentially ignore
                    _id: 0
                }
            }
        ])
        res.status(200).json(posts.concat(...followingPosts[0].followingPosts).sort((a, b) => {
            return b.createdAt - a.createdAt
        }))
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot get timeline posts."})
    }
};