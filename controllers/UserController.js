import UserModel from '../models/UserModel.js';
import bcrypt from 'bcrypt';

//get a user from the database
export const getUser = async (req, res) => {
    //send the id in the parameters of the url
    const id = req.params.id

    try {
        //check if user exists in database
        const user = await UserModel.findById(id)

        //if the user exists, send the user info
        if (user) {
            //all details being received are held within the '_doc' document, breaks apart the response doc into the password and everything else
            const { password, ...otherDetails } = user._doc
            //sends back everything but the password
            res.status(200).json(otherDetails)
        } else {
            res.status(404).json({ message: "User does not exist."})
        }
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot retrieve user from database." })
    }
};

//update a user
export const updateUser = async (req, res) => {
    //send the id of the user you are updating in the parameters of the url
    const id = req.params.id
    //currentUserId is the user performing the update, 
    const { currentUserId, currentUserAdminStatus, password } = req.body

    //conditions that allow a user to update user info
    if (id === currentUserId || currentUserAdminStatus) {
        try {
            //checks if the password is valid
            if (password) {
                //hashes the password in the body of the request for security
                const salt = await bcrypt.genSalt(10)
                req.body.password = await bcrypt.hash(password, salt)
            }
            //id is searching for the specific user to be updates, req.body is the info that is being updated, new=true means that in the response you want to get the updated info back, if you don't specify you'll get the previous info back
            const user = await UserModel.findByIdAndUpdate(id, req.body, {new: true})
            res.status(200).json(user)
        } catch (error) {
            res.status(500).json({ message: "Error: Cannot update user in database."})
        }
    } else {
        res.status(403).json({ message: "Error: Access denied. You may only update your own profile." })
    }
};

export const deleteUser = async (req, res) => {
    const id = req.params.id

    //currentUserId is the user performing the update, 
    const { currentUserId, currentUserAdminStatus } = req.body

    //conditions that allow a user to delete themselves or another user
    if (id === currentUserId || currentUserAdminStatus) {
        try {
            await UserModel.findByIdAndDelete(id)
            res.status(200).json({ message: "User deleted successfully."})
        } catch (error) {
            res.status(500).json({ message: "Error: Cannot delete user."})
        }
    } else {
        res.status(403).json({ message: "Error: Access denied. You do not have permission to delete this user." })
    }
}

export const followUser = async (req, res) => {
    const id = req.params.id

    //gets the current user from the request body 
    const { currentUserId } = req.body

    //conditions that allow a user to follow another user
    if (id === currentUserId) {
        res.status(403).json({ message: "Error: You cannot follow yourself. Weirdo." })
    } else {
        try {
            //defining who you're trying to follow
            const followUser = await UserModel.findById(id)
            //defining the user who is doing the following
            const follower = await UserModel.findById(currentUserId)
            //if the you are NOT already following the followUser, then to both the following and followers arrays, respectively 
            if (!followUser.followers.includes(currentUserId)) {
                await followUser.updateOne({ $push: {followers: currentUserId}});
                await follower.updateOne({ $push: {following: id}})
                res.status(200).json({ message: "Following!"})
            } else {
                res.status(403).json({ message: "You're already following this user." })
            }
        } catch (error) {
            res.status(500).json({ message: "Error: Cannot follow user."})
        }
    }
}