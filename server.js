// server.js

const express = require('express');
const app = express();
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const port = process.env.PORT || 3000;
//const authenticateUser = require('./authenticateUser'); // Reference to the authentication middleware

// Initialize Firebase Admin SDK
const serviceAccount = require('./atman-mobile-firebase-adminsdk-9zjs1-302cbd4ff0.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});


// Middleware for parsing JSON
app.use(express.json());

async function isNicknameTaken(nickname){
    const snapshot = await admin.firestore().collection('users').where('nickname', '==', nickname).get();
    return !snapshot.empty;
}
// Registration route
/*
app.post('/register', async (req, res) => {
    try {
        const { email, password,phonenumber} = req.body;

        // Create a new user in Firebase Authentication
        const userRecord = await admin.auth().createUser({
            email,
            password,
        });

        // Example: Store additional user data in Firestore
        await admin.firestore().collection('users').doc(userRecord.uid).set({
            email,
            phonenumber,
            // Additional user data...
        });

        res.json({ message: 'User registered successfully', uid: userRecord.uid });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
*/
// First Registration Step
app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Create a new user in Firebase Authentication
        const userRecord = await admin.auth().createUser({
            email,
            password,
        });

        // Store additional user data in Firestore
        await admin.firestore().collection('users').doc(userRecord.uid).set({
            email,
            // Additional user data...
        });

        res.json({ uid: userRecord.uid }); // Send the user ID to be used in the next step
    } catch (error) {
        console.error('Error in first registration step:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.post('/userdetails', async (req, res) => {
    try {
        const { uid, name , gender , age , occupation , relationshipstatus , language} = req.body;

      

        // Update user data in Firestore (add or update the nickname)
        await admin.firestore().collection('users').doc(uid).set(
            {
               name , gender , age,occupation,relationshipstatus,language
            },
            { merge: true } // This option ensures that existing data is not overwritten
        );

        res.json({ message: 'User details saved successfully' });
    } catch (error) {
        console.error('Error in user details registration step:', error);
        res.status(500).json({ error: 'Internal Server Error' });
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

        res.json({ message: 'phone number saved successfully' });
    } catch (error) {
        console.error('Error in phone number registration step:', error);
        res.status(500).json({ error: 'Internal Server Error' });
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
            return res.status(400).json({ error: 'Nickname is already taken' });
        }

        // Update user data in Firestore (add or update the nickname)
        await admin.firestore().collection('users').doc(uid).set(
            {
                nickname,
            },
            { merge: true } // This option ensures that existing data is not overwritten
        );

        res.json({ message: 'User nickname added registered successfully' });
    } catch (error) {
        console.error('Error in nickname registration step:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




//login route
// app.post('/login', async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         // Retrieve user by email using the admin SDK
//         const userRecord = await admin.auth().getUserByEmail(email);

//         // Verify the password (this is a simple example, in a real-world scenario, you should use a more secure method)
//         if (userRecord && userRecord.email === email) {
//             // Generate JWT token
//             const token = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, 'kuw', {
//                 expiresIn: '1h', // Token expiration time
//             });

//             // Include the token in the response header
//             res.header('Authorization', `Bearer ${token}`);
//             res.json({ message: 'Login successful', userData: { email: userRecord.email } });
//         } else {
//             res.status(401).json({ error: 'Invalid email or password' });
//         }
//     } catch (error) {
//         console.error('Error during login:', error);

//         // Handle specific authentication errors
//         if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
//             res.status(401).json({ error: 'Invalid email or password' });
//         } else {
//             res.status(500).json({ error: 'Internal Server Error' });
//         }
//     }
// });
app.use(cookieParser());

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Retrieve user by email using the admin SDK
        const userRecord = await admin.auth().getUserByEmail(email);

        // Verify the password (this is a simple example, in a real-world scenario, you should use a more secure method)
        if (userRecord && userRecord.email === email) {
            // Generate JWT access token with a short expiration time
            const accessToken = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, 'yourSecretKey', {
                expiresIn: '15m', // 15 minutes
            });

            // Generate JWT refresh token with a longer expiration time
            const refreshToken = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, 'yourRefreshKey', {
                expiresIn: '7d', // 7 days
            });

            // Set the access and refresh tokens as HTTP cookies
            res.cookie('accessToken', accessToken, {
                httpOnly: true,
                maxAge: 15 * 60 * 1000, // 15 minutes in milliseconds
            });

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
            });

            res.json({
                message: 'Login successful',
                userData: { email: userRecord.email },
            });
        } else {
            res.status(401).json({ error: 'Invalid email or password' });
        }
    } catch (error) {
        console.error('Error during login:', error);

        // Handle specific authentication errors
        if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
            res.status(401).json({ error: 'Invalid email or password' });
        } else {
            res.status(500).json({ error: 'Internal Server Error' });
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
            res.status(401).json({ error: 'Token has already been revoked' });
        } else {
            // Add the token to the blacklist (for demonstration purposes)
            tokenBlacklist.push(token);

            res.json({ message: 'Logout successful' });
        }
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


/*
app.get('/protected-route', authenticateUser, async (req, res) => {
  try {
    // Example: Query data from Firestore using the authenticated user's UID
    const userId = req.uid;
    const userDoc = await admin.firestore().collection('users').doc(userId).get();

    if (userDoc.exists) {
      const userData = userDoc.data();
      res.json({ message: 'This is a protected route', userData });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error querying Firestore:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});*/
/*  // for checking whether firebase connected or not
 app.get('/test-firestore-connection', async (req, res) => {
   try {
     const testDoc = await admin.firestore().collection('test').doc('testDoc').get();
 
     if (testDoc.exists) {
       const testData = testDoc.data();
       res.json({ message: 'Connection to Firestore successful', testData });
     } else {
       res.status(404).json({ error: 'Test document not found in Firestore' });
     }
   } catch (error) {
     console.error('Error querying Firestore:', error);
     res.status(500).json({ error: 'Internal Server Error' });
   }
 });
*/

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
                user:'psycove.innerself@gmail.com' ,            
                pass: 'iapaxkleneqcooid',
            },
            tls: {
              rejectUnauthorized: false, // Accept self-signed certificates
          },
        });
        console.log(otp)
        const mailOptions = {
            from: 'psycove.innerself@gmail.com',
            to: email,
            subject: 'Password Reset OTP',
            text: `Your OTP for password reset is: ${otp}`,
        };
      
        await transporter.sendMail(mailOptions);

        res.json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Error in forgot password route:', error);
        res.status(500).json({ error: 'Internal Server Error' });
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
                res.status(400).json({ error: 'Incorrect OTP' });
            }
        } else {
            // OTP not found in Firestore
            res.status(404).json({ error: 'OTP not found' });
        }
    } catch (error) {
        console.error('Error in verify OTP route:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// ... (Other routes and server setup)

// Start the Express server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
