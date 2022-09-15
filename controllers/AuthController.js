import UserModel from '../models/UserModel.js';
import bcrypt from 'bcrypt';

//new user registration
export const registerUser = async (req, res) => {
    //reqest body contains user info
    const { username, password, firstname, lastname } = req.body;

    //encrypt the password, 10 is the amount of alteration to the password through hashing
    const salt = await bcrypt.genSalt(10)
    const hashedPass = await bcrypt.hash(password, salt)

    //map user input/request into the user model schema
    const newUser = new UserModel({ 
        username, 
        password: hashedPass, 
        firstname, 
        lastname 
    });

    //save the new user to database
    try {
        await newUser.save()
        res.status(200).json(newUser)
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

            //if the password matches/is true send the user from the DB, if it's not true send forbidden
            validity? res.status(200).json(user) : res.status(400).json({ message: "Incorrect password."})
        } else {
            res.status(404).json({ message: "User does not exist."})
        }
    } catch (error) {
        res.status(500).json({ message: "Error: Cannot validate user information."})
    }
}