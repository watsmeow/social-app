import express from 'express'
import { registerUser, loginUser } from '../controllers/AuthController.js'

const router = express.Router()

//calling auth controller
router.post('/register', registerUser)
router.post('/login', loginUser)

export default router