import UserModel from '../models/UserModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

//new user registration
export const registerUser = async (req, res) => {
    //encrypt the password, 10 is the amount of alteration to the password through hashing
    const salt = await bcrypt.genSalt(10)
    const hashedPass = await bcrypt.hash(req.body.password, salt)
    req.body.password = hashedPass
    const {username} = req.body
    //map user input/request into the user model schema
    const newUser = new UserModel(
        req.body
    );

    //save the new user to database
    try {
        //find the user that has the same username exported from req.body
        const oldUser = await UserModel.findOne({username})
        //if the user already exists
        if (oldUser) {
            return res.status(400).json({ message: "Username already exists."})
        }
        //saves and returns the new user
        const user = await newUser.save()
        //username is jwt token signature
        const token = jwt.sign({
            username: user.username, 
            id: user._id
        }, 
        //second parameter is token, third token is the expiration period of the token
        process.env.JWT_KEY, {expiresIn: '1h'})
        res.status(200).json({user, token});
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot save user to database."})
    }
}

//login a user

export const loginUser = async (req, res) => {
    const { username, password } = req.body;
    try {
        //find a user with a username given in the request body, if it exists then it is assigned to user variable
        const user = await UserModel.findOne({ username: username })

        //if the user exists, validate the password
        if (user) {
            //bcrypt compares password received from request with hashed password in the database
            const validity = await bcrypt.compare(password, user.password)
            //if there is no validity don't login, otherwise use token
            if (!validity) {
                res.status(400).json({ message: "Incorrect password."})
            } else {
                const token = jwt.sign({
                    username: user.username, 
                    id: user._id
                }, 
                //second parameter is token, third token is the expiration period of the token
                process.env.JWT_KEY, {expiresIn: '1h'})
                res.status(200).json({user, token});
            }
        } else {
            res.status(404).json({ message: "User does not exist."})
        }
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot validate user information."})
    }
}