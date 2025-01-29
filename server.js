const express = require('express');
const path = require('path');
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require('dotenv').config();

const port = 3000;

app.use(express.json());
const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', './views');

app.use(express.urlencoded({ extended: true }));

const users = [
    {
        username: "Jonh",
        password: "124367890",
    },
    {
        username: "Doe",
        password: "124567890"
    }
];

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    const userExist = users.find(user => user.username === username);

    if (userExist) {
        return res.status(409).send("User already exists!");
    }
    if (!username || !password || !email) {
        return res.status(409).send("Please fill all the information.");
    }
    if (password.length < 8) {
        return res.status(400).send("Password must be at least 8 characters long.");
    }

    const hashPassword = await bcrypt.hash(password, 10);
    console.log(hashPassword);
    
    users.push({
        username: username,
        password: hashPassword
    });

    res.status(201).send("User created successfully.");
});

app.post("/login", async (req, res) => {
    console.log('Users:', users);

    const { username, password } = req.body;

    if (username && password) {
        const user = users.find(user => user.username === username);

        if (!user) {
            return res.status(400).send("Invalid credentials");
        }

        const correctPassword = await bcrypt.compare(password, user.password);

        if (!correctPassword) {
            return res.status(400).send("Enter a correct password!");
        }

        console.log('Secret Key:', process.env.SECRET_KEY);
        
        const usernameData = { username: user.username };
        const access_token = generateAccessToken(usernameData);

        console.log('Access Token:', access_token);
        return res.status(200).json({ access_token });
    } else {
        return res.status(400).send('Username & password are required');
    }
});

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).send('Access token is needed.');
    }
    
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send('Token is invalid');
        }
        req.user = user;
        next();
    });
}

function generateAccessToken(usernameData) {
    return jwt.sign(usernameData, process.env.SECRET_KEY);
}

// Secure feedback route with authentication middleware
app.get('/feedback', authenticateToken, (req, res) => {
    console.log('Rendering feedback form...');
    res.render('user');
});

app.post("/customerfeedback", authenticateToken, (req, res) => {
    const { rating, comments, email } = req.body;

    if (!rating || !comments || !email) {
        return res.status(400).send("All fields are required.");
    }

    // Store the feedback (later, you can use a database)
    const feedback = {
        rating,
        comments,
        email,
        submittedAt: new Date().toISOString()
    };

    console.log("New Feedback Received:", feedback);

    // Send a response back
    res.status(201).send("Thank you for your feedback!");
});


app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
