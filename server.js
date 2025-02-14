require('dotenv').config();
const express = require('express');
const cors = require("cors");
const path = require('path');
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongoose = require('mongoose');

const port = 3000;

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

if (!process.env.CONNECTION_STRING || !process.env.SECRET_KEY) {
    console.error("Missing environment variables.");
    process.exit(1);
}

// MongoDB Connection
(async () => {
    try {
        await mongoose.connect(process.env.CONNECTION_STRING);
        console.log("Database connected successfully!");

        app.listen(port, () => {
            console.log(`Server is running on http://localhost:${port}`);
        });
    } catch (error) {
        console.error("Error connecting to database:", error);
    }
})();

// User Schema & Model
const UserSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String
});
const User = mongoose.model("User", UserSchema);

// Register Route
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !password || !email) {
        return res.status(400).send("Please fill all the information.");
    }
    if (password.length < 8) {
        return res.status(400).send("Password must be at least 8 characters long.");
    }

    const userExist = await User.findOne({ email });
    if (userExist) {
        return res.status(409).send("User already exists!");
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashPassword });
    await newUser.save();

    res.status(201).send("User created successfully.");
});

// Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email & password are required');
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).send("Invalid credentials");
    }

    const correctPassword = await bcrypt.compare(password, user.password);
    if (!correctPassword) {
        return res.status(400).send("Enter a correct password!");
    }

    const access_token = generateAccessToken({ username: user.username });
    return res.status(200).json({ access_token });
});

// Generate JWT
function generateAccessToken(usernameData) {
    return jwt.sign(usernameData, process.env.SECRET_KEY, { expiresIn: '1h' });
}

// Secure Token Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Access token is needed.');
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send('Token is invalid');
        }
        req.user = user;
        next();
    });
}

// Secure Feedback Route
app.get('/feedback', authenticateToken, (req, res) => {
    console.log('Rendering feedback form...');
    res.render('user');
});

// Feedback Submission Route
app.post("/customerfeedback", authenticateToken, (req, res) => {
    const { rating, comments, email } = req.body;

    if (!rating || !comments || !email) {
        return res.status(400).send("All fields are required.");
    }

    console.log("New Feedback Received:", { rating, comments, email, submittedAt: new Date().toISOString() });
    res.status(201).send("Thank you for your feedback!");
});