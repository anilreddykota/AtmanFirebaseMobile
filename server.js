// server.js
const express = require('express');
const app = express();
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt=require("bcrypt")
const nodemailer = require('nodemailer');
const port = process.env.PORT || 3000;
const authenticateUser = require('./authenticateUser'); // Reference to the authentication middleware

// Initialize Firebase Admin SDK

const serviceAccount = require('./atman-mobile-firebase-adminsdk-9zjs1-302cbd4ff0.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});


// Middleware for parsing JSON
app.use(express.json());

async function isNicknameTaken(nickname) {
  const snapshot = await admin.firestore().collection('users').where('nickname', '==', nickname).get();
  return !snapshot.empty;
}

app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Hash the password using bcrypt with a salt factor of 10
    const hashedPassword = await bcrypt.hash(password, 15);

    // Create a new user in Firebase Authentication with email and hashed password
    const userRecord = await admin.auth().createUser({
      email,
      password: hashedPassword,
    });

    // Access the user UID from the userRecord
    const userUid = userRecord.uid;

    // Store additional user data in Firestore (excluding password)
    const userData = {
      email,
      password:hashedPassword
    };
    await admin.firestore().collection('users').doc(userUid).set(userData);

    // Respond with a success message and user UID
    res.json({ message: 'Registration successful', uid: userUid });
  } catch (error) {
    console.error('Error in registration:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/userdetails', async (req, res) => {
  try {
    const { uid, name, gender, age, occupation, relationshipstatus, language } = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('users').doc(uid).set(
      {
        name, gender, age, occupation, relationshipstatus, language
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );

    res.json({ message: 'User details saved successfully', uid:uid });
  } catch (error) {
    console.error('Error in user details registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/registerphonenumber', async (req, res) => {
  try {
    const { uid, phonenumber } = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('users').doc(uid).set(
      {
        phonenumber,
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );
    res.json({ message: 'phone number saved successfully', uid: uid });
  } catch (error) {
    console.error('Error in phone number registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
// Second Registration Step
// Second Registration Step
app.post('/registernickname', async (req, res) => {
  try {
    const { uid, nickname } = req.body;
    // Check if the nickname is already taken
    const nicknameExists = await isNicknameTaken(nickname);
    if (nicknameExists) {
      return res.status(400).json({ message: 'Nickname is already taken' });
    }
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('users').doc(uid).set(
      {
        nickname,
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );
    res.json({ message: 'User nickname added registered successfully', uid: uid });
  } catch (error) {
    console.error('Error in nickname registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// login route


app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Retrieve user by email using the admin SDK
    const userRecord = await admin.auth().getUserByEmail(email);
    if (userRecord) {
    // Retrieve user data from Firestore, assuming you have a 'users' collection
    const userDoc = await admin.firestore().collection('users').doc(userRecord.uid).get();

    if (userDoc.exists) {
      // Check if the user has a nickname
      const userNickname = userDoc.data().nickname;
      if (!userNickname) {
        return res.status(401).json({ message: 'In complete Registration' });
      }

      // Retrieve hashed password from Firestore
      const storedHashedPassword = userDoc.data().password;

      // Verify the entered password with the stored hashed password
      const isPasswordValid = await bcrypt.compare(password, storedHashedPassword);

      if (isPasswordValid) {
        // Generate JWT token with user UID and email
        const token = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, 'atmanapplication', {
          expiresIn: '1h', // Token expiration time (e.g., 1 hour)
        });

        // Include the token in the response header and respond with user data
        res.header('Authorization', `Bearer ${token}`);
        res.json({
          message: 'Login successful',
          userData: { email: userRecord.email, uid: userRecord.uid, nickname: userNickname },
          tokenExpiresIn: 3600, // Expiration time in seconds (1 hour)
        });
      } else {
        res.status(401).json({ message: 'Invalid email or password' });
      }
    } else {
      res.status(404).json({ message: 'User not found in Firestore' });
    }
  } else {
    res.status(404).json({ message: 'User not found' });
  }
  } catch (error) {
    console.error('Error during login:', error);

    // Handle specific authentication errors
    if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
      res.status(401).json({ message: 'Invalid email or password' });
    } else {
      res.status(500).json({ message: 'Internal Server Error' });
    }
  }
});

const tokenBlacklist = [];
//logout route
app.post('/logout', (req, res) => {
  try {
    // Extract token from the Authorization header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    // Check if the token is in the blacklist
    if (token && tokenBlacklist.includes(token)) {
      res.status(401).json({ message: 'Token has already been revoked' });
    } else {
      // Add the token to the blacklist (for demonstration purposes)
      tokenBlacklist.push(token);

      res.json({ message: 'Logout successful' });
    }
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




// Generate an OTP and send it to the user's email
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Retrieve user by email using the admin SDK
    const userRecord = await admin.auth().getUserByEmail(email);
    const otpLength = 6;
    let otp = '';

    for (let i = 0; i < otpLength; i++) {
      otp += Math.floor(Math.random() * 10).toString();
    }
    // Save the OTP in Firestore (or any other persistent storage)
    await admin.firestore().collection('otp').doc(userRecord.uid).set({
      otp,
    });

    // Send OTP to user's email
    const transporter = nodemailer.createTransport({
      // Configure your email service here
      service: 'gmail',
      auth: {
        user: 'psycove.innerself@gmail.com',
        pass: 'kjrqzsjvbapkoqbw',
      },
      tls: {
        rejectUnauthorized: false, // Accept self-signed certificates call gmeet /
      },
    });
    console.log(otp)
    const mailOptions = {
      from: 'psycove.innerself@gmail.com',
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}`
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error in forgot password route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/verify-otp', async (req, res) => {
  try {
    const { uid, enteredOtp } = req.body;

    // Retrieve stored OTP from Firestore
    const otpDoc = await admin.firestore().collection('otp').doc(uid).get();

    if (otpDoc.exists) {
      const storedOtp = otpDoc.data().otp;

      // Compare entered OTP with stored OTP
      if (enteredOtp === storedOtp) {
        // OTP is correct, you can proceed with further actions (e.g., password reset)
        res.json({ message: 'OTP verification successful' });
      } else {
        // Incorrect OTP
        res.status(400).json({ message: 'Incorrect OTP' });
      }
    } else {
      // OTP not found in Firestore
      res.status(404).json({ message: 'OTP not found' });
    }
  } catch (error) {
    console.error('Error in verify OTP route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// ... (Other routes and server setup)

// Start the Express server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});