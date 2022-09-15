import express from 'express';
import { deleteUser, followUser, getUser, updateUser } from '../controllers/UserController.js';

const router = express.Router();

//get request, not sending any info using the body of the request because the user ID is in the url of the request
router.get('/:id', getUser)

//update user in DB
router.put('/:id', updateUser)

//delete a user
router.delete('/:id', deleteUser)

//follow another user
router.put('/:id/follow', followUser)

export default router;