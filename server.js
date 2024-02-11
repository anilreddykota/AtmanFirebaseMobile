// server.js
const express = require('express');
const app = express();
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt=require("bcrypt")
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const upload = multer();

// const port = process.env.PORT || 3001;
const port = 3001;
const cors = require('cors'); 
app.use(cors());
//const authenticateUser = require('./authenticateUser'); // Reference to the authentication middleware

// Initialize Firebase Admin SDK

const serviceAccount = require('./newkey.json');
const { Timestamp } = require('@google-cloud/firestore');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: 'psycove-4ebf5.appspot.com'
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
  const snapshot = await admin.firestore().collection('users').doc("userDetails").collection("details").where('nickname', '==', nickname).get();
  return !snapshot.empty;
}


app.post('/registerUser', async (req, res) => {
  try {
      const { email, password } = req.body;

      // Check if user exists
      let existingUserRecord;
      try {
          existingUserRecord = await admin.auth().getUserByEmail(email);
      } catch (error) {
          // If no user record found, proceed with registration
          if (error.code !== 'auth/user-not-found') {
              throw error; // Rethrow other errors
          }
      }

      if (existingUserRecord) {
          // User already exists
          const userData = existingUserRecord.toJSON();
          if (!userData || !userData.nickname) {
              // User doesn't have a nickname, update details and re-register
              await updateUserAndReRegister(existingUserRecord.uid, email, password);
              return res.json({ message: 'User details updated and re-registered successfully', uid: existingUserRecord.uid });
          } else {
              // User already registered with a nickname
              return res.status(400).json({ message: 'you are already registered  try with other email', error: 'User already registered with a nickname' });
          }
      } else {
          // User doesn't exist, create a new user
          const userRecord = await admin.auth().createUser({
              email,
              password: await bcrypt.hash(password, 15)
          });

          // Store user details in Firestore
          await admin.firestore().collection('users').doc("userDetails").collection("details").doc(userRecord.uid).set({
              email,
              password: userRecord.passwordHash
          });

          // Respond with a success message and user UID
          return res.json({ message: 'Registration successful', uid: userRecord.uid });
      }
  } catch (error) {
      console.error('Error in registration:', error);
      return res.status(500).json({ message: 'Internal Server Error', error: error.message });
  }
});

async function updateUserAndReRegister(uid, email, password) {
  try {
      // Check if user already has a nickname
      const userDoc = await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).get();
      if (userDoc.exists) {
          const userData = userDoc.data();
          if (userData && userData.nickname) {
              // User already registered with a nickname, throw error
              throw new Error('User already registered with a nickname');
          }
      }

      // Delete existing user document
      await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).delete();

      // Re-register the user with the same UID
      const hashedPassword = await bcrypt.hash(password, 15);
      await admin.auth().updateUser(uid, {
          password: hashedPassword
      });

      // Update user details in Firestore
      await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).set({
          email,
          password: hashedPassword
      });

      // Return success message
      return { message: 'User details updated and re-registered successfully', uid };
  } catch (error) {
      // Handle specific error case: User already registered with a nickname
      if (error.message === 'User already registered with a nickname') {
          throw error;
      }
      // Handle other errors
      throw new Error('Error updating user details and re-registering');
  }
}






    
    
//     // User already exists
//     // Check if user has a nickname
//     const userDoc = await admin.firestore().collection('users').doc("userDetails").collection("details").doc(existingUserRecord.uid).get();
//     if (userDoc.exists) {
//       const userData = userDoc.data();
//       if (!userData || !userData.nickname) {
//         // Delete existing user details
//         await admin.firestore().collection('users').doc("userDetails").collection("details").doc(existingUserRecord.uid).delete();
//         // Re-register the user with the same UID
//         const hashedPassword = await bcrypt.hash(password, 15);
//         await admin.auth().updateUser(existingUserRecord.uid, {
//           password: hashedPassword,
//         });
//         // Update user details in Firestore
//         const newUserDetails = {
//           email,
//           password: hashedPassword
//         };
//         await admin.firestore().collection('users').doc("userDetails").collection("details").doc(existingUserRecord.uid).set(newUserDetails);
//         // Respond with success message and user UID
//         return res.json({ message: 'User details updated and re-registered successfully', uid: existingUserRecord.uid });
//       }
//       // User already registered with a nickname, return error
//       return res.status(400).json({ message: 'User already registered' });
//     } else {
//       // User document does not exist in Firestore, register the user
//       const hashedPassword = await bcrypt.hash(password, 15);
//       const userRecord = await admin.auth().createUser({
//         email,
//         password: hashedPassword,
//       });
//       // Store user details in Firestore
//       const userData = {
//         email,
//         password: hashedPassword
//       };
//       await admin.firestore().collection('users').doc("userDetails").collection("details").doc(userRecord.uid).set(userData);
//       // Respond with a success message and user UID
//       return res.json({ message: 'Registration successful', uid: userRecord.uid });
//     }
    
//   } catch (error) {
//     console.error('Error in registration:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// }
// );







app.post('/userdetails', async (req, res) => {
  try {
    const { uid, name, gender, age, occupation, relationshipstatus, language } = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).set(
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

app.post('/registerUserNickname', async (req, res) => {
  try {
    const { uid, nickname } = req.body;
    // Check if the nickname is already taken
    const nicknameExists = await isNicknameTaken(nickname);
    if (nicknameExists) {
      return res.status(400).json({ message: 'Nickname is already taken' });
    }
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).set(
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
app.post('/UserLogin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Retrieve user by email using the admin SDK
    const userRecord = await admin.auth().getUserByEmail(email);

    if (userRecord) {
      // Retrieve user data from Firestore, assuming you have a 'users' collection
      const userDocRef = admin.firestore().collection('users').doc("userDetails").collection("details").doc(userRecord.uid);
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

app.post('/generateOtp', async (req, res) => {
  try {
    const { uid, email } = req.body;

    // Generate a random OTP
    const otpLength = 4;
    let otp = '';
    for (let i = 0; i < otpLength; i++) {
      otp += Math.floor(Math.random() * 10).toString();
    }

    // Save the OTP in Firestore under the user's UID
    await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).update({
      otp,
    });

    // Send OTP to the user's email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'psycove.innerself@gmail.com',
        pass: 'kjrqzsjvbapkoqbw',
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

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
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


// POST method for verify-otp endpoint
app.post('/verify-otp', async (req, res) => {
  try {
    const { uid, enteredOtp } = req.body;

    // Retrieve stored OTP from Firestore using the provided UID
    const otpDocRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid);
    const otpDoc = await otpDocRef.get();

    if (otpDoc.exists) {
      const storedOtp = otpDoc.data().otp;

      // Compare entered OTP with stored OTP
      if (enteredOtp === storedOtp) {
        // OTP verification successful
        // Delete the OTP from Firestore
        await otpDocRef.update({ otp: admin.firestore.FieldValue.delete() });
        res.status(200).json({ message: 'OTP verification successful' });
      } else {
        // Incorrect OTP
        res.status(400).json({ message: 'Incorrect OTP' });
      }
    } else {
      // OTP not found in Firestore
      res.status(404).json({ message: 'OTP not found' });
    }
  } catch (error) {
    console.error('Error in POST verify OTP route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




// Middleware to get the current question count
async function getCurrentQuestionCount() {
  const snapshot = await admin.firestore().collection('questions').get();
  return snapshot.size + 1; // Incrementing the count for the next question
}
// app.post('/store-question', async (req, res) => {
//   try {
//     const { question } = req.body;

//     // Get the reference to the document
//     const dailyJournalRef = admin.firestore().collection('users').doc('dailyjournal');

//     // Get the current questions data
//     const dailyJournalDoc = await dailyJournalRef.get();
//     let dailyJournalData = dailyJournalDoc.exists ? dailyJournalDoc.data() : { questions: {} };

//     // Get the index for the new question
//     const index = Object.keys(dailyJournalData.questions).length + 1;

//     // Add the new question to the questions object with the index mapping
//     dailyJournalData.questions[index] = question;

//     // Update the document in Firestore
//     await dailyJournalRef.set(dailyJournalData);

//     res.json({ message: 'Question stored successfully', index, question });
//   } catch (error) {
//     console.error('Error in store-question route:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });



// app.get('/get-next-question', async (req, res) => {
//   try {
//     // Get the reference to the document containing the last fetched question index
//     const indexDocRef = admin.firestore().collection('users').doc('dailyjournal').collection('lastFetchedQuestionIndex');
    
//     // Get the current index data
//     const indexDoc = await indexDocRef.get();
//     let lastFetchedQuestionIndex = indexDoc.exists ? indexDoc.data().index : 0;

//     // Query the next question
//     let query = admin.firestore().collection('users').doc('dailyjournal').collection('questions').doc(lastFetchedQuestionIndex.toString());

//     // Get the next question
//     const questionDoc = await query.get();

//     if (questionDoc.exists) {
//       const nextQuestion = questionDoc.data().question;
      
//       // Increment the index for the next question
//       lastFetchedQuestionIndex++;

//       // Update the last fetched question index in Firestore
//       await indexDocRef.set({ index: lastFetchedQuestionIndex });

//       res.json({ question: nextQuestion });
//     } else {
//       res.status(404).json({ message: 'No questions found' });
//     }
//   } catch (error) {
//     console.error('Error in get-next-question route:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });
// Initialize with 0
app.post('/store-question', async (req, res) => {
  try {
    const { question } = req.body;

    // Get the reference to the dailyjournal document
    const dailyJournalRef = admin.firestore().collection('users').doc('dailyjournal');

    // Get the current data of the dailyjournal document
    const dailyJournalDoc = await dailyJournalRef.get();
    let dailyJournalData = dailyJournalDoc.exists ? dailyJournalDoc.data() : { questions: [] };

    // Ensure questions field is initialized as an array
    if (!Array.isArray(dailyJournalData.questions)) {
      dailyJournalData.questions = [];
    }

    // Add the new question to the questions array with the index mapping
    dailyJournalData.questions.push({ question });

    // Update the dailyjournal document in Firestore
    await dailyJournalRef.set(dailyJournalData);

    res.json({ message: 'Question stored successfully', question });
  } catch (error) {
    console.error('Error in store-question route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.get('/get-next-question', async (req, res) => {
  try {
    // Get the reference to the dailyjournal document
    const dailyJournalRef = admin.firestore().collection('users').doc('dailyjournal');

    // Get the current data of the dailyjournal document
    const dailyJournalDoc = await dailyJournalRef.get();
    const dailyJournalData = dailyJournalDoc.exists ? dailyJournalDoc.data() : { questions: [] };

    // Check if there are questions available
    if (dailyJournalData.questions.length > 0) {
      // Get the index of the next question
      let nextQuestionIndex = dailyJournalData.nextQuestionIndex || 0;

      // Get the next question from the questions array
      const nextQuestion = dailyJournalData.questions[nextQuestionIndex].question;

      // Increment the index for the next question
      nextQuestionIndex = (nextQuestionIndex + 1) % dailyJournalData.questions.length;

      // Update the next question index in the document
      await dailyJournalRef.update({ nextQuestionIndex });

      res.json({ question: nextQuestion });
    } else {
      res.status(404).json({ message: 'No questions found' });
    }
  } catch (error) {
    console.error('Error in get-next-question route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




app.post('/create-post', upload.single('image'), async (req, res) => {
  try {
    const { title, description } = req.body;
    const { buffer } = req.file;

    // Upload the image to Firebase Storage
    const imageFilename = `${uuidv4()}.jpg`;
    const storageRef = admin.storage().bucket().file(imageFilename);
    await storageRef.save(buffer, { contentType: 'image/jpeg' });

    // Get the URL of the uploaded image
    const imageUrl =  `https://firebasestorage.googleapis.com/v0/b/${storageRef.bucket.name}/o/${encodeURIComponent(
      imageFilename
    )}?alt=media`;
    // Get the current date
    const currentDate = new Date();

    // Create a new post object
    const post = {
      title,
      description,
      imageUrl,
      date: currentDate,
      approved: 0
    };

    // Reference to the "posts" document in the "users" collection
    const postsDocRef = admin.firestore().collection('users').doc('posts');

    // Retrieve the current posts data
    const postsDoc = await postsDocRef.get();

    if (postsDoc.exists) {
      // If the "posts" document already exists, update it with the new post
      await postsDocRef.update({
        posts: admin.firestore.FieldValue.arrayUnion(post)
      });
    } else {
      // If the "posts" document does not exist, create it with the new post
      await postsDocRef.set({
        posts: [post]
      });
    }

    res.json({ message: 'Post created successfully' });
  } catch (error) {
    console.error('Error in create-post route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/get-unapproved-posts', async (req, res) => {
  try {
    // Get all posts where approved is 0
    const postsSnapshot = await admin.firestore().collection('posts').where('approved', '==', 0).get();

    // Extract post data from snapshot
    const unapprovedPosts = postsSnapshot.docs.map(doc => doc.data());

    console.log('All unapproved posts:', unapprovedPosts); // Log for debugging

    res.json({ unapprovedPosts });
  } catch (error) {
    console.error('Error in get-unapproved-posts route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/get-posts', async (req, res) => {
  try {
    // Reference to the "posts" document in the "users" collection
    const postsDocRef = admin.firestore().collection('users').doc('posts');

    // Retrieve the current posts data
    const postsDoc = await postsDocRef.get();

    if (postsDoc.exists) {
      const postsData = postsDoc.data();
      // Sort posts by date in descending order
      const sortedPosts = postsData.posts.sort((a, b) => b.date - a.date);
      res.json({ posts: sortedPosts });
    } else {
      res.status(404).json({ message: 'No posts found' });
    }
  } catch (error) {
    console.error('Error in get-posts route:', error);
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
app.post('/create-work-goal', async (req, res) => {
  try {
    const { uid, workGoal } = req.body;

    // Get the current date
    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on user's UID and the formatted date
    const workGoalRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid)
                            .collection('workGoal').doc(formattedDate);

    // Set the work goal document with the provided work goal and current date
    await workGoalRef.set({
      workGoal,
      date: currentDate,
    }, { merge: true }); // Merge with existing data if document already exists

    res.json({ message: 'Work goal created successfully', goalId: workGoalRef.id });
  } catch (error) {
    console.error('Error in create-work-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/create-personal-goal', async (req, res) => {
  try {
    const { uid, personalGoal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on the user's UID and the formatted date
    const personalGoalRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('personal_goal').doc(formattedDate);

    // Update the personal goal or create a new document if it doesn't exist
    await personalGoalRef.set({
      personalGoal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Personal goal updated successfully', goalId: personalGoalRef.id });
  } catch (error) {
    console.error('Error in create-personal-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.get('/get-daily-goal', async (req, res) => {
  try {
    const { uid } = req.query;

    if (!uid) {
      return res.status(400).json({ message: 'UID parameter is required' });
    }

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the daily goal document for the specified user and date
    const dailyGoalRef = admin.firestore().collection('users').doc(uid).collection('daily_goal').doc(formattedDate);

    // Get the daily goal document
    const dailyGoalDoc = await dailyGoalRef.get();

    if (dailyGoalDoc.exists) {
      const dailyGoalData = dailyGoalDoc.data();
      res.json({ message: 'Daily goal retrieved successfully', dailyGoal: dailyGoalData });
    } else {
      res.status(404).json({ message: 'Daily goal not found for the specified user and date' });
    }
  } catch (error) {
    console.error('Error in get-daily-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/create-career-goal', async (req, res) => {
  try {
    const { uid, careerGoal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on the user's UID and the formatted date
    const careerGoalRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('career_goal').doc(formattedDate);

    // Update the career goal or create a new document if it doesn't exist
    await careerGoalRef.set({
      careerGoal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Career goal updated successfully', goalId: careerGoalRef.id });
  } catch (error) {
    console.error('Error in create-career-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/create-family-goal', async (req, res) => {
  try {
    const { uid, familyGoal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on the user's UID and the formatted date
    const familyGoalRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('family_goal').doc(formattedDate);

    // Update the family goal or create a new document if it doesn't exist
    await familyGoalRef.set({
      familyGoal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Family goal updated successfully', goalId: familyGoalRef.id });
  } catch (error) {
    console.error('Error in create-family-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/create-learning-goal', async (req, res) => {
  try {
    const { uid, learningGoal } = req.body;

    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);

    // Create a reference to the document based on the user's UID and the formatted date
    const learningGoalRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('learning_goal').doc(formattedDate);

    // Update the learning goal or create a new document if it doesn't exist
    await learningGoalRef.set({
      learningGoal,
      date: currentDate,
    }, { merge: true });

    res.json({ message: 'Learning goal updated successfully', goalId: learningGoalRef.id });
  } catch (error) {
    console.error('Error in create-learning-goal route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/add-rating', async (req, res) => {
  try {
    const { uid, techniqueId, rating } = req.body;

    // Get the current date
    const currentDate = new Date();

    // Create a reference to the document based on user's UID and the specified technique ID
    const ratingRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid)
                            .collection('coupingTechniques').doc(techniqueId);

    // Get the existing data of the specified technique
    const techniqueDoc = await ratingRef.get();
    let techniqueData = techniqueDoc.exists ? techniqueDoc.data() : {};

    // Get the current index for storing the rating
    const currentIndex = Object.keys(techniqueData).length;

    // Add the rating to the technique document with the current index
    techniqueData[currentIndex] = { rating, date: currentDate };

    // Update the document with the new rating
    await ratingRef.set(techniqueData, { merge: true });

    res.json({ message: 'Rating added successfully', ratingId: currentIndex });
  } catch (error) {
    console.error('Error in add-rating route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});












// API to create family goal for a user

app.post('/questions', async (req, res) => {
  try {
    const { set, text, options, scores } = req.body;

    // Create a reference to the 'users' collection
    const usersCollectionRef = admin.firestore().collection('users');

    // Create a reference to the 'selftest' subcollection under 'users'
    const selfTestCollectionRef = usersCollectionRef.doc('selftest').collection('questions');

    // Get the current index for the set
    const setDoc = await selfTestCollectionRef.doc(set).get();
    let currentIndex = 1; // Default to 1 if set doesn't exist

    if (setDoc.exists) {
      const setData = setDoc.data();
      const questionIds = Object.keys(setData);
      currentIndex = questionIds.length + 1;
    }

    // Add the question directly to the specified set with the current index
    const questionRef = await selfTestCollectionRef.doc(set).set({
      [currentIndex]: {
        text,
        options,
        scores,
      },
    }, { merge: true });

    res.json({ message: 'Question added successfully', questionId: currentIndex });
  } catch (error) {
    console.error('Error adding question:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/submit-answers', async (req, res) => {
  try {
    const { uid, answers } = req.body;

    // Create a reference to the user's document
    const userDocRef = admin.firestore().collection('users').doc(uid);

    // Get the current date
    const currentDate = new Date().toISOString();

    // Create a reference to the 'selftest' subcollection for the current date
    const selfTestCollectionRef = userDocRef.collection('selftest').doc(currentDate);

    // Set the answers within the 'selftest' subcollection
    await selfTestCollectionRef.set({ answers });

    // Calculate the overall score and individual set scores
    const overallScore = calculateOverallScore(answers);
    const setScores = calculateSetScores(answers);

    res.json({ message: 'Answers submitted successfully', overallScore, setScores });
  } catch (error) {
    console.error('Error submitting answers:', error);
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
app.get('/get-nickname/:uid', async (req, res) => {
  try {
    const uid = req.params.uid;

    // Retrieve user data from Firestore using the provided UID
    const userDocRef = admin.firestore().collection('users').doc("userDetails").collection().doc(uid);
    const userDoc = await userDocRef.get();

    if (userDoc.exists) {
      // Check if the user has a nickname
      const userNickname = userDoc.data().nickname;

      if (userNickname) {
        res.json({ nickname: userNickname });
      } else {
        res.status(404).json({ message: 'Nickname not found for the provided UID' });
      }
    } else {
      res.status(404).json({ message: 'User not found for the provided UID' });
    }
  } catch (error) {
    console.error('Error getting nickname:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

async function authenticatePsychologist(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Unauthorized - Missing token' });
  try {
    // Verify the JWT token against Firebase Authentication
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    // Add the user UID to the request object for further processing
    req.psychologistid = decodedToken.puid;

    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ message: 'Unauthorized - Invalid token' });
  }
}

//checking Name of psychologists
async function isPsychologistNicknameTaken(nickname) {
  const snapshot = await admin.firestore().collection('psychologists').doc("psychologistDetails").collection("details").where('nickname', '==', nickname).get();
  return !snapshot.empty;
}

//register the psychologists name 
app.post('/registerPsychologist', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Hash the password using bcrypt with a salt factor of 15
    const hashedPassword = await bcrypt.hash(password, 15);

    // Create a new user in Firebase Authentication with email and hashed password
    const psychologistRecord = await admin.auth().createUser({
      email,
      password: hashedPassword,
    });

    // Access the user UID from the psychologistRecord
    const psychologistUid = psychologistRecord.uid;

    // Store additional user data in Firestore (excluding password)
    const psychologistData = {
      email,
      password:hashedPassword
    };
    await admin.firestore().collection('psychologists').doc('psychologistDetails').collection('details').doc(psychologistUid).set(psychologistData);

    // Respond with a success message and user UID
    res.json({ message: 'Registration successful', puid: psychologistUid });
  } catch (error) {
    console.error('Error in registration:', error);

    // Check for the specific error code related to existing email
    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({ message: 'Email address already in use' });
    }

    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/psychologistdetails', async (req, res) => {
  try {
    const { puid, name, gender, age, languages, area_of_expertise} = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('psychologists').doc('psychologistDetails').collection('details').doc(puid).set(
      {
        name, gender, age, languages, area_of_expertise
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );

    res.json({ message: 'Psychologist details saved successfully', puid:puid });
  } catch (error) {
    console.error('Error in psychologist details registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/registerPsychologistPhoneNumber', async (req, res) => {
  try {
    const { puid, phonenumber } = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('psychologists').doc('psychologistDetails').collection('details').doc(puid).set(
      {
        phonenumber,
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );
    res.json({ message: 'phone number saved successfully', puid: puid });
  } catch (error) {
    console.error('Error in phone number registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/registerPsychologistNickname', async (req, res) => {
  try {
    const { puid, nickname } = req.body;
    // Check if the nickname is already taken
    const nicknameExists = await isPsychologistNicknameTaken(nickname);
    if (nicknameExists) {
      return res.status(400).json({ message: 'Nickname is already taken' });
    }
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('psychologists').doc('psychologistDetails').collection('details').doc(puid).set(
      {
        nickname,
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );
    res.json({ message: 'Psychologist nickname added registered successfully', puid: puid }); 
  } catch (error) {
    console.error('Error in nickname registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

//psychologist login route
app.post('/psychologistLogin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Retrieve psychologist by email using the admin SDK
    const psychologistRecord = await admin.auth().getUserByEmail(email);
    if (psychologistRecord) {
      // Retrieve psychologist data from Firestore, assuming you have a 'psychologists' collection
      const psychologistDocRef = admin.firestore().collection('psychologists').doc("psychologistDetails").collection("details").doc(psychologistRecord.uid);
      const psychologistDoc = await psychologistDocRef.get();
      
      if (psychologistDoc.exists) {
        // Check if the psychologist has a nickname
        
        // Retrieve hashed password from Firestore
        const storedHashedPassword = psychologistDoc.data().password;

        // Verify the entered password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, storedHashedPassword);

        if (isPasswordValid) {
          // Generate JWT token with psychologist UID and email
          const token = jwt.sign({ puid: psychologistRecord.puid, email: psychologistRecord.email }, 'atmanapplication', {

          });

          // Include the token in the response header and respond with psychologist data
          res.header('Authorization', `Bearer ${token}`);
          res.json({
            message: 'Login successful',
               userData: { email: psychologistRecord.email, uid: psychologistRecord.uid },

          });
        } else {
          res.status(401).json({ message: 'Invalid email or password' });
        }
      } else {
        res.status(404).json({ message: 'Psychologist not found in Firestore' });
      }
    } else {
      res.status(404).json({ message: 'Psychologist not found' });
    }
  } catch (error) {
    console.error('Error during login:', error);

    // Handle specific authentication errors
    if (error.code === 'auth/user-not-found' )  {
      res.status(401).json({ message: 'Invalid email' });
    }else if(error.code === 'auth/wrong-password'){
      res.status(401).json({ message: 'Invalid password' });
    } else {
      res.status(500).json({ message: 'Internal Server Error' });
    }
  }
});

const psychologistTokenBlacklist = [];
//logout route
app.post('/psychologistLogout', (req, res) => {
  try {
    // Extract token from the Authorization header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    // Check if the token is in the blacklist
    if (token && psychologistTokenBlacklist.includes(token)) {
      res.status(401).json({ message: 'Token has already been revoked' });
    } else {
      // Add the token to the blacklist (for demonstration purposes)
      psychologistTokenBlacklist.push(token);

      res.json({ message: 'Logout successful' });
    }
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
//book Appointment
app.post('/bookAppointment', async (req, res) => {
  try {
    const { uid, date, timeSlot, puid } = req.body;

    // Reference to the 'bookings' subcollection for the specified 'puid'
    const pendingAppointmentsRef = admin.firestore().collection('psychologists').doc(puid).collection("pending").doc("pending");

    // Get the existing document data
    const existingData = (await pendingAppointmentsRef.get()).data() || { bookings: [] };

    // Check if there is an existing appointment for the specified time slot
    const existingAppointment = existingData.bookings.find(appointment => appointment.timeSlot === timeSlot);

    if (existingAppointment) {
      // Appointment for the same time slot and puid already exists
      return res.status(400).json({ message: 'Appointment for the same time slot and doctor already exists.' });
    }

    // Add the new booking to the array
    existingData.bookings.push({
      uid: uid,
      date: date,
      timeSlot: timeSlot,
    });

    // Update the document with the new array of bookings
    await pendingAppointmentsRef.set(existingData);

    res.json({ message: 'Appointment booked successfully' });
  } catch (error) {
    console.error('Error booking appointment:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



app.post('/updateAppointmentStatus', async (req, res) => {
  try {
    const { uid, puid, status } = req.body;

    // Check if the required parameters are provided
    if (!uid || !puid || !status) {
      return res.status(400).json({ message: 'Invalid request. Missing uid, puid, or status.' });
    }

    // Reference to the 'pending' subcollection for the specified 'puid'
    const pendingAppointmentsRef = admin.firestore().collection('psychologists').doc(puid).collection("pending").doc("pending");

    // Get the existing document data from the 'pending' collection
    const pendingAppointmentsData = (await pendingAppointmentsRef.get()).data();

    // Check if the appointment exists in the 'pending' collection
    if (!pendingAppointmentsData) {
      return res.status(404).json({ message: 'Pending appointments not found' });
    }

    // Find the appointment with the specified uid
    const appointmentToUpdate = pendingAppointmentsData.bookings.find(appointment => appointment.uid === uid);

    if (!appointmentToUpdate) {
      return res.status(404).json({ message: 'Appointment not found for the specified uid' });
    }

    // Remove the appointment from the 'pending' collection
    const updatedBookings = pendingAppointmentsData.bookings.filter(appointment => appointment.uid !== uid);
    await pendingAppointmentsRef.set({ bookings: updatedBookings });

    // If the status is 'approved', move the appointment to the 'approved' collection
    if (status === 'approved') {
      // Reference to the 'approved' subcollection for the specified 'puid'
      const approvedAppointmentsRef = admin.firestore().collection('psychologists').doc(puid).collection("approved").doc("approved");

      // Get the existing document data from the 'approved' collection
      const approvedAppointmentsData = (await approvedAppointmentsRef.get()).data() || { bookings: [] };

      // Add the appointment to the array in the 'approved' collection
      approvedAppointmentsData.bookings.push(appointmentToUpdate);

      // Update the document in the 'approved' collection with the new array of bookings
      await approvedAppointmentsRef.set(approvedAppointmentsData);
    }

    res.json({ message: 'Appointment status updated successfully' });
  } catch (error) {
    console.error('Error updating appointment status:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/getAppointmentsByDoctor', async (req, res) => {
  try {
    const { puid } = req.body;
    if (!puid) {
      return res.status(400).json({ message: 'Invalid request. Missing puid parameter in the request body.' });
    }

    // Reference to the 'pending' subcollection for the specified 'puid'
    const pendingAppointmentsRef = admin.firestore().collection('psychologists').doc(puid).collection("pending").doc("pending");

    // Reference to the 'approved' subcollection for the specified 'puid'
    const approvedAppointmentsRef = admin.firestore().collection('psychologists').doc(puid).collection("approved").doc("approved");

    // Get the existing document data for pending appointments
    const pendingAppointmentsData = (await pendingAppointmentsRef.get()).data() || { bookings: [] };

    // Get the existing document data for approved appointments
    const approvedAppointmentsData = (await approvedAppointmentsRef.get()).data() || { bookings: [] };

    const pendingAppointments = pendingAppointmentsData.bookings;
    const approvedAppointments = approvedAppointmentsData.bookings;

    res.json({
      pendingAppointments: pendingAppointments,
      approvedAppointments: approvedAppointments
    });
  } catch (error) {
    console.error('Error retrieving appointments:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/addAppointmentToDoctorList', async (req, res) => {
  try {
    const { puid, nickname } = req.body;

    // Check if both puid and nickname are provided
    if (!puid || !nickname) {
      return res.status(400).json({ message: 'Invalid request. Missing puid or nickname parameter in the request body.' });
    }

    // Get the UID associated with the provided nickname
    const userSnapshot = await admin.firestore()
      .collection('users')
      .doc("userDetails")
      .collection("details")
      .where('nickname', '==', nickname)
      .limit(1)
      .get();

    if (userSnapshot.empty) {
      return res.status(404).json({ message: 'User with the provided nickname not found.' });
    }

    // Assuming there's only one user with the provided nickname, get their UID
    const userData = userSnapshot.docs[0];
    const uid = userData.id;

    // Reference the document in the 'doctorAppointments' collection corresponding to the provided puid
    const doctorAppointmentRef = admin.firestore().collection('psychologists').doc(puid).collection("approved").doc("addedbyPsych");

    // Get the existing data from the document
    const existingData = (await doctorAppointmentRef.get()).data();

    // Check if the UID already exists in the array
    if (existingData && existingData.uids && existingData.uids.includes(uid)) {
      return res.status(400).json({ message: 'Appointment with the same client already exists.' });
    }

    // If the document already exists, update the array of UIDs
    if (existingData) {
      const updatedUids = [...(existingData.uids || []), uid];

      await doctorAppointmentRef.update({
        uids: updatedUids,
       
      });

      return res.json({ message: 'Appointment added to the doctor list successfully', puid: puid });
    }

    // If the document does not exist, create a new document with the array of UIDs
    await doctorAppointmentRef.set({
      uids: [uid],
     
    });

    res.json({ message: 'Appointment added to the doctor list successfully', puid: puid });
  } catch (error) {
    console.error('Error adding appointment to the doctor list:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




app.post("/assignTasksToClient", async (req, res) => {
  try {
    const { uid, puid, tasks } = req.body;
    
    // Check if all required parameters are provided
    if (!uid || !puid || !tasks || !Array.isArray(tasks)) {
      return res.status(400).json({ message: 'Invalid request. Missing uid, puid, or tasks parameter in the request body.' });
    }

    // Reference a new document in the 'tasksToClients' collection (Firestore will generate a unique ID)
    const tasksToClientRef = admin.firestore().collection('appointments').doc('Conversations').collection('tasksToClients').doc();

    // Get the generated ID from the document reference
    const taskId = tasksToClientRef.id;

    // Set data for the specific document, including the task ID, doctor's user id, client's user id, and tasks array
    await tasksToClientRef.set({
      taskId: taskId,
      puid: puid,
      uid: uid,
      tasks: tasks,
      status: "assigned"
    
    });

    res.json({ message: 'Tasks assigned to client successfully', taskId: taskId });
  } catch (error) {
    console.error('Error assigning tasks to client:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/createChatConversation', async (req, res) => {
  try {
    const { uid, puid } = req.body;

    // Check if both uid and puid are provided
    if (!uid || !puid) {
      return res.status(400).json({ message: 'Invalid request. Missing uid or puid parameter in the request body.' });
    }

    // Check if a conversation already exists between uid and puid
    const existingConversationQuery = await admin.firestore()
      .collection('appointments')
      .doc('Conversations')
      .collection('chatConversations')
      .where('uid', '==', uid)
      .where('puid', '==', puid)
      .limit(1)
      .get();

    if (!existingConversationQuery.empty) {
      // Conversation already exists, return the existing conversation ID
      const existingConversationData = existingConversationQuery.docs[0].data();
      const existingConversationId = existingConversationData.conversationId;
      return res.json({ message: 'Chat conversation already exists', conversationId: existingConversationId });
    }

    // Reference a new document in the 'chatConversations' collection (Firestore will generate a unique ID)
    const chatConversationRef = admin.firestore().collection('appointments').doc('Conversations').collection('chatConversations').doc();

    // Get the generated ID from the document reference
    const conversationId = chatConversationRef.id;

    // Set data for the specific document, including the conversation ID, client's user id, psychologist's user id, and any other relevant information
    await chatConversationRef.set({
      conversationId: conversationId,
      uid: uid,
      puid: puid,
      messages: [], // Initialize with an empty array for messages
    });

    res.json({ message: 'Chat conversation created successfully', conversationId: conversationId });
  } catch (error) {
    console.error('Error creating chat conversation:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Send message route
app.post('/sendMessage', async (req, res) => {
  try {
    const { conversationId, senderUid, message } = req.body;

    // Check if required parameters are provided
    if (!conversationId || !senderUid || !message) {
      return res.status(400).json({ message: 'Invalid request. Missing conversationId, senderUid, or message parameter in the request body.' });
    }

    // Reference the chat conversation document
    const chatConversationRef = admin.firestore().collection('appointments').doc('Conversations').collection('chatConversations').doc(conversationId);

    // Get the current conversation data
    const chatConversationDoc = await chatConversationRef.get();
    const conversationData = chatConversationDoc.data();

    // Ensure that the sender is either the client or the psychologist in the conversation
    if (senderUid !== conversationData.uid && senderUid !== conversationData.puid) {
      return res.status(403).json({ message: 'Forbidden. Sender is not allowed in this conversation.' });
    }

    // Get the current messages array
   

    // Get the current timestamp
    const timestamp = new Date().toISOString();

    // Update the messages array in the conversation document
    await chatConversationRef.update({
      messages: admin.firestore.FieldValue.arrayUnion({
        senderUid: senderUid,
        message: message,
        timestamp: timestamp,
      }),
    });

    res.json({ message: 'Message sent successfully' });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Retrieve messages route
app.get('/getMessages/:conversationId', async (req, res) => {
  try {
    const { conversationId } = req.params;

    // Check if conversationId is provided
    if (!conversationId) {
      return res.status(400).json({ message: 'Invalid request. Missing conversationId parameter in the request.' });
    }

    // Reference the chat conversation document
    const chatConversationRef = admin.firestore().collection('appointments').doc('Conversations').collection('chatConversations').doc(conversationId);

    // Get the chat conversation document
    const chatConversationDoc = await chatConversationRef.get();

    if (!chatConversationDoc.exists) {
      return res.status(404).json({ message: 'Chat conversation not found.' });
    }

    const chatConversationData = chatConversationDoc.data();

    res.json({ messages: chatConversationData.messages || [] });
  } catch (error) {
    console.error('Error retrieving messages:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/generateAccesstoken' , async(req, res) => {
  // For demonstration purposes, let's assume you receive user data in the request body
  const user = req.body;

  try {
      const accessToken = generateAccessToken(user);
      res.status(200).json({ accessToken: accessToken });
  } catch (error) {
      console.error('Error generating access token:', error.message);
      res.status(500).json({ error: 'Failed to generate access token' });
  }
});

// Function to generate an access token
function generateAccessToken(user) {
  // Define payload for the token (can include any user-related data)
  const payload = {
      userId: user.id,
      email: user.email,
      // You can include additional data if needed
  };

  //Set the secret key
  const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;

  // Define options (optional)
  const options = {
      expiresIn: '15m' // Token expires in 15 minutes
  };

  // Generate the access token
  const accessToken = jwt.sign(payload, accessTokenSecret, options);

  return accessToken;
}
app.post(generateRefreshtoken = (req, res) => {
    // For demonstration purposes, let's assume you receive user data in the request body
    const user = req.body;
  
    try {
        const refreshToken = generateRefreshToken(user);
        res.status(200).json({ refreshToken: refreshToken });
    } catch (error) {
        console.error('Error generating refresh token:', error.message);
        res.status(500).json({ error: 'Failed to generate refresh token' });
    }
  });
  
  // Function to generate refresh token
  function generateRefreshToken(user) {
    // Define payload for the token (can include any user-related data)
    const payload = {
        userId: user.id,
        email: user.email,
        // You can include additional data if needed
    };
  
    //Set the secret key
    const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
  
  
    // Define options (optional)
    const options = {
        expiresIn: '7d' // Token expires in 7 days
    };
  
    // Generate the refresh token
    const refreshToken = jwt.sign(payload, refreshTokenSecret, options);
  
    return refreshToken;
  }
  
// chat soket.io routes
// const http = require('http');
// const socketIO = require('socket.io');
// const server = http.createServer(app);
// const io = socketIO(server, {
//   cors: {
//     origin: 'http://localhost:3000',
//     methods: ['GET', 'POST'],
//   },
// });



// Start the Express server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
