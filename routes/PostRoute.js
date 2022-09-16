import express from 'express';
import {createPost, deletePost, getPost, getTimeLinePosts, likePost, updatePost} from '../controllers/PostController.js'
const router = express.Router();

//make a post
router.post('/', createPost)
//get a post
router.get('/:id', getPost)
//update a post
router.put('/:id', updatePost)
//delete a post
router.delete('/:id', deletePost)
//like a post
router.put('/:id/like', likePost)
//get timeline posts
router.get('/:id/timeline', getTimeLinePosts)



export default router;