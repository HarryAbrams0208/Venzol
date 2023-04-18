const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require('./models/user');
const passport = require('passport');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();
const router = express.Router();
const port = process.env.PORT || 5000;
const cors = require('cors');
const keys = require("./config/keys.js");
const { OAuth2Client } = require("google-auth-library");
const axios = require('axios');
mongoose.connect('mongodb://127.0.0.1:27017/Venzol', { useNewUrlParser: true })
        .then(() => console.log("MongoDB Connected"))
        .catch(err => console.log("MongoDB is not connected"));
app.use(
  bodyParser.urlencoded({
    extended: false
  })
);
app.use(bodyParser.json());

app.use(passport.initialize());
require("./config/passport.js")(passport);

const corsOptions ={
  origin:'http://localhost:3000', 
  credentials:true,            //access-control-allow-credentials:true
  optionSuccessStatus:200
}
app.use(cors(corsOptions));



app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  // Validate user data
  if (!name || !email || !password) {
    console.log('Please provide all required fields');
    return res.status(400).json({ message: 'Please provide all required fields' });
  }
  // Check if user already exists
  const existingUser = await User.findOne({ $or: [{ name }, { email }] });

  if (existingUser) {
    console.log(name + 'User already exists');
    return res.status(409).json({ message: 'User already exists' });
  }

  // Create new user
  const newUser = new User({ name : name, email : email, password: password });

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (err, hash) => {
      if (err) throw err;
      newUser.password = hash;
      newUser.save();
    });
  });
  console.log(name + ' User created successfully');
  return res.json({ message: 'User created successfully' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('/api/login');
  await User.findOne({
    email
  }).then(user => {
    if (!user) {
      console.log('User not found');
      return res.status(400).json({ message: 'User not found' });
    }

    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        const payload = { id: user.id, name: user.name};
        jwt.sign(
          payload,
          "myScret",
          { expiresIn: 360000 },
          (err, token) => {
            res.json({
              success: true,
              token: "Bearer " + token
            });
          }
        );
        console.log('Login successful');
      } else {
        console.log('Password incorrect');
        return res.status(400).json({ message: 'Password incorrect' });
      }
    });
  });
});

// Our database
let DB = [];

/**
 *  This function is used verify a google account
 */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

async function verifyGoogleToken(token) {
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });
    return { payload: ticket.getPayload() };
  } catch (error) {
    return { error: "Invalid user detected. Please try again" };
  }
}

app.post('/api/login/google', async (req, res) => {
  try {
    console.log('api/login/google');
    if (req.body.credential) {
      const verificationResponse = await verifyGoogleToken(req.body.credential);
      if (verificationResponse.error) {
      console.log(verificationResponse.error);
        return res.status(400).json({
          message: verificationResponse.error,
        });
      }

      const profile = verificationResponse?.payload;

      const existsInDB = DB.find((person) => person?.email === profile?.email);

      if (!existsInDB) {
        console.log('You are not registered. Please sign up');
        return res.status(400).json({
          message: "You are not registered. Please sign up",
        });
      }
      console.log('Google Login was successful');
      res.status(201).json({
        message: "Login was successful",
        user: {
          firstName: profile?.given_name,
          lastName: profile?.family_name,
          email: profile?.email,
          token: jwt.sign({ email: profile?.email }, "myScret", {
            expiresIn: "1d",
          }),
        },
      });
    }
  } catch (error) {
    res.status(500).json({
      message: error?.message || error,
    });
  }
});

app.post("/api/signup/google", async (req, res) => {
  try {
    // console.log({ verified: verifyGoogleToken(req.body.credential) });
    if (req.body.credential) {
      const verificationResponse = await verifyGoogleToken(req.body.credential);

      if (verificationResponse.error) {
        return res.status(400).json({
          message: verificationResponse.error,
        });
      }

      const profile = verificationResponse?.payload;

      DB.push(profile);
      console.log('Signup was sucessful');
      res.status(201).json({
        message: "Signup was successful",
        user: {
          firstName: profile?.given_name,
          lastName: profile?.family_name,
          picture: profile?.picture,
          email: profile?.email,
          token: jwt.sign({ email: profile?.email }, "myScret", {
            expiresIn: "1d",
          }),
        },
      });
    }
  } catch (error) {
    console.log('An error occured. Registration failed.');
    res.status(500).json({
      message: "An error occured. Registration failed.",
    });
  }
});


app.post('/api/forgetpwd', async (req, res) => {
  const { email } = req.body;
  console.log('/api/forgetpwd');
  await User.findOne({
    email
  }).then(user => {
    if (!user) {
      console.log('User not found');
      return res.status(400).json({ message: 'User not found' });
    }
  });
});

app.post('/api/lockScr', 
  async (req, res) => {
  console.log('api/lockScr');
  const { password } = req.body;
  console.log(password);
  const authHeader = req.headers.authorization;
  console.log(authHeader);
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  const user = jwt.verify(token, "myScret");
  req.user = user;
  await User.findOne({
    name: req.user.name
  }).then(user => {
    if (!user) {
      console.log('User not found');
      return res.status(400).json({ message: 'User not found' });
    }

    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        console.log('Password match');
        return res.json({ message: 'Password match' });
      } else {
        console.log('Password incorrect');
        return res.status(400).json({ message: 'Password incorrect' });
      }
    });
  });
});

app.get(
  "/current",
  (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    const user = jwt.verify(token, "myScret");
    req.user = user;
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email
    });
  }
);

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});