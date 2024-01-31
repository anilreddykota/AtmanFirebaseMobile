// server.js
const express = require('express');
const app = express();
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt=require("bcrypt")
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const port = process.env.PORT || 3000;
//const authenticateUser = require('./authenticateUser'); // Reference to the authentication middleware

// Initialize Firebase Admin SDK

const serviceAccount = require('./atman-mobile-firebase-adminsdk-9zjs1-302cbd4ff0.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});


// Middleware for parsing JSON
app.use(express.json());

//authenticateuser
async function authenticateUser(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Unauthorized - Missing token' });

  try {
    // Verify the JWT token against Firebase Authentication
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    // Add the user UID to the request object for further processing
    req.userUid = decodedToken.uid;

    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ message: 'Unauthorized - Invalid token' });
  }
}

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
      const userDocRef = admin.firestore().collection('users').doc(userRecord.uid);
      const userDoc = await userDocRef.get();

      if (userDoc.exists) {
        // Check if the user has a nickname
        const userNickname = userDoc.data().nickname;

        if (!userNickname) {
          // Remove user details if registration is incomplete
          await userDocRef.delete();
          return res.status(401).json({ message: 'Incomplete Registration - User details removed' });
        }

        // Retrieve hashed password from Firestore
        const storedHashedPassword = userDoc.data().password;

        // Verify the entered password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, storedHashedPassword);

        if (isPasswordValid) {
          // Generate JWT token with user UID and email
          const token = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, 'atmanapplication', {

          });

          // Include the token in the response header and respond with user data
          res.header('Authorization', `Bearer ${token}`);
          res.json({
            message: 'Login successful',
            userData: { email: userRecord.email, uid: userRecord.uid, nickname: userNickname },
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
    const otpLength = 4;
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
    const otpDocRef = admin.firestore().collection('otp').doc(uid);
    const otpDoc = await otpDocRef.get();

    if (otpDoc.exists) {
      const storedOtp = otpDoc.data().otp;

      // Compare entered OTP with stored OTP
      if (enteredOtp === storedOtp) {
        // OTP verification successful
        // Delete the OTP from Firestore
        await otpDocRef.delete();
        res.status(200).json({ message: 'OTP verification successful' });
      } else {
        // Incorrect OTP
        // Also, delete the incorrect OTP from Firestore for security
        await otpDocRef.delete();
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
// Middleware to get the current question count
async function getCurrentQuestionCount() {
  const snapshot = await admin.firestore().collection('questions').get();
  return snapshot.size + 1; // Incrementing the count for the next question
}
app.post('/store-question', async (req, res) => {
  try {
    const { question } = req.body;

    // Get the reference to the document
    const questionsDocRef = admin.firestore().collection('questionCollection').doc('dailyjournalquestions');

    // Get the current questions data
    const questionsDoc = await questionsDocRef.get();
    let questionsData = questionsDoc.exists ? questionsDoc.data() : { questions: [] };

    // Add the new question to the array with an index
    const newQuestion = { index: questionsData.questions.length + 1, question };
    questionsData.questions.push(newQuestion);

    // Update the document in Firestore
    await questionsDocRef.set(questionsData);

    res.json({ message: 'Question stored successfully', newQuestion });
  } catch (error) {
    console.error('Error in store-question route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.get('/get-next-question', async (req, res) => {
  try {
    // Get the reference to the document containing the last fetched question index
    const indexDocRef = admin.firestore().collection('questionCollection').doc('lastFetchedQuestionIndex');
    
    // Get the current index data
    const indexDoc = await indexDocRef.get();
    let lastFetchedQuestionIndex = indexDoc.exists ? indexDoc.data().index : 0;

    // Query the next question
    let query = admin.firestore().collection('questionCollection').doc('dailyjournalquestions');

    // If lastFetchedQuestionIndex is available, query the next question after it
    query = query.get();
    const questionsDoc = await query;

    if (questionsDoc.exists) {
      const questionsData = questionsDoc.data();
      const questions = questionsData.questions;

      if (lastFetchedQuestionIndex >= questions.length) {
        // If the index exceeds the number of questions, reset to 1
        lastFetchedQuestionIndex = 0;
      }

      const nextQuestion = questions[lastFetchedQuestionIndex];
      lastFetchedQuestionIndex++;

      // Update the last fetched question index in Firestore
      await indexDocRef.set({ index: lastFetchedQuestionIndex });

      res.json({ question: nextQuestion });
    } else {
      res.status(404).json({ message: 'No questions found' });
    }
  } catch (error) {
    console.error('Error in get-next-question route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});//updated

let lastFetchedQuestionIndex = 0; // Initialize with 0

// Endpoint to get the next question in sequence
// app.get('/get-next-question', async (req, res) => {
//   try {
//     let query = admin.firestore().collection('questions').limit(1);

//     // If lastFetchedQuestionIndex is available, query the next question after it
//     if (lastFetchedQuestionIndex !== null) {
//       query = query.where('index', '>', lastFetchedQuestionIndex).limit(1);
//     }

//     const nextQuestionSnapshot = await query.get();

//     if (nextQuestionSnapshot.empty) {
//       // If no more questions are found, reset to index 1 and query again
//       lastFetchedQuestionIndex = 0;
//       query = admin.firestore().collection('questions').where('index', '>', lastFetchedQuestionIndex).limit(1);
//       const repeatedQuestionSnapshot = await query.get();

//       if (repeatedQuestionSnapshot.empty) {
//         res.status(404).json({ message: 'No questions found' });
//       } else {
//         const repeatedQuestion = repeatedQuestionSnapshot.docs[0].data();
//         lastFetchedQuestionIndex = repeatedQuestion.index; // Update the last fetched question index
//         res.json({ question: repeatedQuestion });
//       }
//     } else {
//       const nextQuestion = nextQuestionSnapshot.docs[0].data();
//       lastFetchedQuestionIndex = nextQuestion.index; // Update the last fetched question index
//       res.json({ question: nextQuestion });
//     }
//   } catch (error) {
//     console.error('Error in get-next-question route:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });//original


app.post('/create-post', async (req, res) => {
  try {
    const { uid, title, description, imageBase64 } = req.body;

    // Decode the base64-encoded image
    const imageBuffer = Buffer.from(imageBase64, 'base64');

    // Generate a unique filename for the image using uuid
    const imageFilename = `${uuidv4()}.jpg`;

    // Upload the image to Firebase Storage
    const storageRef = admin.storage().bucket().file(imageFilename);
    await storageRef.save(imageBuffer, { contentType: 'image/jpeg' });

    // Get the URL of the uploaded image
    const imageUrl = `https://storage.googleapis.com/${storageRef.bucket.name}/${imageFilename}`;

    // Get the current date
    const currentDate = new Date();

    // Store the user's post in a collection (e.g., 'posts') with the image URL
    const postRef = await admin.firestore().collection('posts').add({
      uid,
      title,
      description,
      imageUrl, // Store the image URL in Firestore
      date: currentDate,
    });

    res.json({ message: 'Post created successfully', postId: postRef.id });
  } catch (error) {
    console.error('Error in create-post route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Function to check if a goal exists for the current date
const doesGoalExistForDate = async (uid, subcollection, currentDate) => {
  const snapshot = await admin.firestore().collection('users').doc(uid).collection(subcollection)
    .where('date', '==', currentDate)
    .get();

  return !snapshot.empty;
};

// API to create daily goal for a user
// Function to get the document reference for a goal on a specific date
const getGoalDocumentRefForDate = async (uid, subcollection, currentDate) => {
  const snapshot = await admin.firestore().collection('users').doc(uid).collection(subcollection)
    .where('date', '==', currentDate)
    .get();

  if (!snapshot.empty) {
    // If a document exists for the current date, return its reference
    return snapshot.docs[0].ref;
  }

  return null;
};
// API to create daily goal for a user
// Function to format the date as a string for use in the document ID
const formatDateForDocumentId = (date) => {
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}-${month}-${day}`;
};

// API to create daily goal for a user
app.post('/create-daily-goal', async (req, res) => {
  try {
    const { uid, goal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on user's UID and the formatted date
    const dailyGoalRef = admin.firestore().collection('users').doc(uid).collection('daily_goal').doc(formattedDate);

    // Update the goal or create a new document if it doesn't exist
    await dailyGoalRef.set({
      goal,
      date: currentDate,
    }, { merge: true }); // Use merge option to update existing fields without overwriting

    res.json({ message: 'Daily goal updated successfully', goalId: dailyGoalRef.id });
  } catch (error) {
    console.error('Error in create-daily-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
// API to create career goal for a user
app.post('/create-career-goal', async (req, res) => {
  try {
    const { uid, goal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on user's UID and the formatted date
    const careerGoalRef = admin.firestore().collection('users').doc(uid).collection('career_goal').doc(formattedDate);

    // Update the goal or create a new document if it doesn't exist
    await careerGoalRef.set({
      goal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Career goal updated successfully', goalId: careerGoalRef.id });
  } catch (error) {
    console.error('Error in create-career-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// API to create learning goal for a user
app.post('/create-learning-goal', async (req, res) => {
  try {
    const { uid, goal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on user's UID and the formatted date
    const learningGoalRef = admin.firestore().collection('users').doc(uid).collection('learning_goal').doc(formattedDate);

    // Update the goal or create a new document if it doesn't exist
    await learningGoalRef.set({
      goal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Learning goal updated successfully', goalId: learningGoalRef.id });
  } catch (error) {
    console.error('Error in create-learning-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// API to create personal goal for a user
app.post('/create-personal-goal', async (req, res) => {
  try {
    const { uid, goal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on user's UID and the formatted date
    const personalGoalRef = admin.firestore().collection('users').doc(uid).collection('personal_goal').doc(formattedDate);

    // Update the goal or create a new document if it doesn't exist
    await personalGoalRef.set({
      goal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Personal goal updated successfully', goalId: personalGoalRef.id });
  } catch (error) {
    console.error('Error in create-personal-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// API to create family goal for a user
app.post('/create-family-goal', async (req, res) => {
  try {
    const { uid, goal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on user's UID and the formatted date
    const familyGoalRef = admin.firestore().collection('users').doc(uid).collection('family_goal').doc(formattedDate);

    // Update the goal or create a new document if it doesn't exist
    await familyGoalRef.set({
      goal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Family goal updated successfully', goalId: familyGoalRef.id });
  } catch (error) {
    console.error('Error in create-family-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
// API to store a question in a specific set
// API to store a question in a specific set
app.post('/questions', async (req, res) => {
  try {
    const { set, text, options, scores } = req.body;

    // Create a reference to the document 'questions'
    const questionsDocRef = admin.firestore().collection('selftest').doc('questions');

    // Add the question to the specified set subcollection
    const questionRef = await questionsDocRef.collection(set).add({
      text,
      options,
      scores,
    });

    res.json({ message: 'Question added successfully', questionId: questionRef.id });
  } catch (error) {
    console.error('Error adding question:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/change-password', authenticateUser, async (req, res) => {
  try {
    const { uid, currentPassword, newPassword } = req.body;

    // Retrieve user data from Firestore
    const userDoc = await admin.firestore().collection('users').doc(uid).get();
    const userData = userDoc.data();

    // Verify the current password
    const passwordMatch = await bcrypt.compare(currentPassword, userData.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash the new password
    const newHashedPassword = await bcrypt.hash(newPassword, 15);

    // Update the password in Firebase Authentication
    await admin.auth().updateUser(uid, {
      password: newHashedPassword,
    });

    // Update the password in Firestore
    await admin.firestore().collection('users').doc(uid).update({
      password: newHashedPassword,
    });

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error in changing password:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
// Start the Express server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});