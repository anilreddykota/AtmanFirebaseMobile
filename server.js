// server.js
const express = require('express');
const app = express();
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt")
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const upload = multer();

const port = 3001;
const cors = require('cors');
app.use(cors());

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
  const { token, uid } = req.body;

  if (!token) return res.json({ message: 'Unauthorized - Missing token' });


  try {
    const snapshot = await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).get();
    if (snapshot.data().token === token) {
      console.log("verified token");
      next();
    } else {
      res.json({ message: "send-to-logout" })
    }
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
        return res.json({ message: 'registration`', uid: existingUserRecord.uid });
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

    res.json({ message: 'User details saved successfully', uid: uid });
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
        profile: 'https://firebasestorage.googleapis.com/v0/b/psycove-4ebf5.appspot.com/o/defaultpic.jpeg?alt=media'
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );
    res.json({ message: 'User nickname added registered successfully', uid: uid });
  } catch (error) {
    console.error('Error in nickname registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.post('/protected-route-user', async (req, res) => {
  try {
    const { token, uid } = req.body;
    if (!token) return res.json({ message: 'Unauthorized - Missing token' });
    const snapshot = await admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid).get();
    if (snapshot.data().token === token) {
      console.log("verified token");
    } else {
      res.json({ message: "send-to-logout" })
    }
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ message: 'Unauthorized - Invalid token' });
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
          const token = jwt.sign({ uid: userRecord.uid, email: userRecord.email }, 'atmanapplication', {

          });
          await userDocRef.update({ token: token })

          // Include the token in the response header and respond with user data
          res.header('Authorization', `Bearer ${token}`);
          res.json({
            message: 'Login successful',
            userData: { email: userRecord.email, uid: userRecord.uid, nickname: userNickname, token: token },
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
app.post('/logout-user', async (req, res) => {
  try {
    // Extract uid from the request body
    const { uid } = req.body;
    console.log(uid);

    // Get reference to the user document in Firestore
    const userDocRef = admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid);

    // Get the user document data
    const userDocSnapshot = await userDocRef.get();

    // Check if the user document exists
    if (!userDocSnapshot.exists) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    // Get the token from the user document data
    const token = userDocSnapshot.data().token;

    // Remove the token from the user document
    await userDocRef.update({ token: admin.firestore.FieldValue.delete() });

  
      res.json({ message: 'Logout successful' });
  
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
async function getCurrentQuestionCount() {
  const snapshot = await admin.firestore().collection('questions').get();
  return snapshot.size + 1; // Incrementing the count for the next question
}
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
    const { title, description, uid } = req.body;
    const { buffer } = req.file;

    // Upload the image to Firebase Storage
    const imageFilename = `${uuidv4()}.jpg`;
    const storageRef = admin.storage().bucket().file(imageFilename);
    await storageRef.save(buffer, { contentType: 'image/jpeg' });

    // Get the URL of the uploaded image
    const imageUrl = `https://firebasestorage.googleapis.com/v0/b/${storageRef.bucket.name}/o/${encodeURIComponent(
      imageFilename
    )}?alt=media`;
    // Get the current date
    const currentDate = new Date();

    // Create a new post object
    const post = {
      uid,
      title,
      description,
      imageUrl,
      date: currentDate,
      likesCount: 0
    };

    // Reference to the "pending" subcollection under the "posts" document in the "users" collection
    const pendingPostsCollectionRef = admin.firestore().collection('users').doc('posts').collection('pending');

    // Add the new post document to the "pending" subcollection
    await pendingPostsCollectionRef.add(post);

    res.json({ message: 'Post created successfully' });
  } catch (error) {
    console.error('Error in create-post route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/like-post', async (req, res) => {

  const postId = req.query.postid;
  const uid = req.query.uid;
  try {

    console.log(postId, uid);
    await admin.firestore().runTransaction(async transaction => {
      const postRef = admin.firestore().collection('approvedPosts').doc(postId);
      const doc = await transaction.get(postRef);

      if (doc && doc.data && typeof doc.data === 'function') {
        const likesCount = doc.data()?.likesCount || 0;
        // Use likesCount here...
        ;

        const postSnapshot = await postRef.get();
        const postData = postSnapshot.data();

        // Check if the user already liked the post
        if (postData && postData.likedBy && postData.likedBy.likes && postData.likedBy.likes[uid]) {
          console.log('User already liked this post');
          // Send an error response
          return res.status(200).json({ message: 'User already liked this post' });
        } else {
          try {
            // If the user hasn't liked the post yet, update the document
            await transaction.update(postRef, {
              [`likedBy.likes.${uid}` || `likedBy.likes.admin`]: true,
              likesCount: likesCount + 1 // Increment the like count
            });
            // Send a success response
            return res.json({ message: 'Post liked successfully' });
          } catch (error) {
            console.log('Error liking post:', error);
            // Send an error response
            return res.status(500).json({ error: 'Internal Server Error' });
          }
        }


      } else {
        console.error('Invalid document or missing data.');
        // Handle the case where doc is undefined or doesn't have a data() method
      }


    });
  } catch (e) {
    console.log(e);
  }
});
app.post('/dislike-post', async (req, res) => {
  try {
    const postId = req.query.postid;
    const uid = req.query.uid;

    // Update the like status for the user in the post document
    await admin.firestore().runTransaction(async transaction => {
      const postRef = admin.firestore().collection('approvedPosts').doc(postId);
      const doc = await transaction.get(postRef);
      const likesCount = doc.data().likesCount || 0;

      // Remove the like for the user from the post document
      await transaction.update(postRef, {
        [`likedBy.likes.${uid}`]: admin.firestore.FieldValue.delete(),
        likesCount: Math.max(likesCount - 1, 0) // Decrement the like count
      });
    });

    res.json({ message: 'Post disliked successfully' });
  } catch (error) {
    console.error('Error disliking post:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


const doesGoalExistForDate = async (uid, subcollection, currentDate) => {
  const snapshot = await admin.firestore().collection('users').doc(uid).collection(subcollection)
    .where('date', '==', currentDate)
    .get();

  return !snapshot.empty;
};

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
const formatDateForDocumentId = (date) => {
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}-${month}-${day}`;
};

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
app.post('/submit-daily-mood', async (req, res) => {
  try {
    const { uid, answer } = req.body;

    // Get the current date
    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);
    console.log(formattedDate)
    const answerRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('mood').doc(formattedDate);



    // Set the answer document with the provided answer and current date
    await answerRef.set({
      answer
    }, { merge: true }); // Merge with existing data if document already exists

    res.json({ message: 'Daily mood tracked successfully', answerId: answerRef.id });
  } catch (error) {
    console.error('Error in submit-daily-journal-answer route:', error);
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

app.post('/submit-daily-journal-answer', async (req, res) => {
  try {
    const { uid, answer } = req.body;

    // Get the current date
    const currentDate = new Date();
    const formattedDate = formatDateForDocumentId(currentDate);
    console.log(formattedDate)
    const answerRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('dailyjournalanswers').doc(formattedDate);



    // Set the answer document with the provided answer and current date
    await answerRef.set({
      answer,
      date: currentDate,
    }, { merge: true }); // Merge with existing data if document already exists

    res.json({ message: 'Daily journal answer submitted successfully', answerId: answerRef.id });
  } catch (error) {
    console.error('Error in submit-daily-journal-answer route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.get('/daily-journal-date', async (req, res) => {
  try {
    const { uid, date } = req.query;

    if (!uid || !date) {
      return res.status(400).json({ message: 'Both uid and date parameters are required' });
    }

    // Retrieve the answer document from Firestore
    const docRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).collection('dailyjournalanswers').doc(date);
    const doc = await docRef.get();

    // Check if the document exists
    if (!doc.exists) {
      return res.status(404).json({ message: 'Answer not found for the provided date' });
    }

    // Extract the answer from the document
    const answer = doc.data().answer;

    // Send the answer in the response
    res.json({ answer });
  } catch (error) {
    console.error('Error in daily-journal-date route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.get('/random-questions', async (req, res) => {
  try {
    // Create a reference to the 'users' collection
    const usersCollectionRef = admin.firestore().collection('users');

    // Get all sets
    const setsSnapshot = await usersCollectionRef.doc('selftest').collection('questions').get();

    let allQuestions = [];

    // Iterate through each set
    setsSnapshot.forEach(setDoc => {
      const setData = setDoc.data();
      Object.entries(setData).forEach(([key, value]) => {
        // Extract set, text, options, scores, and index for each question
        const { text, options, scores } = value;
        const question = { set: setDoc.id, text, options, scores, index: parseInt(key) };
        allQuestions.push(question);
      });
    });

    // Shuffle the array of all questions
    allQuestions.sort(() => Math.random() - 0.5);

    res.json(allQuestions);
  } catch (error) {
    console.error('Error fetching random questions:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
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


app.post('/change-password', async (req, res) => {
  try {
    const { uid, currentPassword, newPassword } = req.body;
    // Retrieve user data from Firestore
    const userDoc = await admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).get();
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
    await admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid).update({
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
    const userDocRef = admin.firestore().collection('users').doc("userDetails").collection().doc(uid);
    const userDoc = await userDocRef.get();

    if (userDoc.exists) {
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
    const decodedToken = await admin.auth().verifyIdToken(token);

    // Add the user UID to the request object for further processing
    req.psychologistid = decodedToken.puid;

    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ message: 'Unauthorized - Invalid token' });
  }
}

async function isPsychologistNicknameTaken(nickname) {
  const snapshot = await admin.firestore().collection('psychologists').where('nickname', '==', nickname).get();
  return !snapshot.empty;
}

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
      password: hashedPassword
    };
    await admin.firestore().collection('psychologists').doc(psychologistUid).set(psychologistData);

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

app.post('/registerPsychologistonweb', async (req, res) => {
  try {
    const { email, password, nickname, area_of_expertise } = req.body;

    // Hash the password using bcrypt with a salt factor of 15
    const hashedPassword = await bcrypt.hash(password, 15);

    // Create a new user in Firebase Authentication with email and hashed password
    const psychologistRecord = await admin.auth().createUser({
      email,
      password: hashedPassword,
      nickname,
      area_of_expertise
    });

    // Access the user UID from the psychologistRecord
    const psychologistUid = psychologistRecord.uid;

    // Store additional user data in Firestore (excluding password)
    const psychologistData = {
      email,
      password: hashedPassword,
      nickname,
      area_of_expertise
    };
    await admin.firestore().collection('psychologists').doc(psychologistUid).set(psychologistData);

    // Respond with a success message and user UID
    res.json({ message: 'Registration successful', puid: psychologistUid });
  } catch (error) {
    console.error('Error in registration:', error);

    // Check for the specific error code related to existing email
    if (error.code === 'auth/email-already-exists') {
      return res.json({ message: 'Email address already in use' });
    }

    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/psychologistBio', async (req, res) => {
  try {
    const { puid, bio } = req.body;
    // Update user data in Firestore (add or update the biography and set visibility to true)
    await admin.firestore().collection('psychologists').doc(puid).set(
      {
        bio,
        visibility: true
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );
    res.json({ message: 'Biography saved successfully', puid: puid });
  } catch (error) {
    console.error('Error in saving psychologist biography:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/hidePsychologistProfile', async (req, res) => {
  try {
    const { puid } = req.body;

    await admin.firestore().collection('psychologists').doc(puid).update({
      visibility: false
    });

    res.json({ message: 'Psychologist profile hidden successfully', puid: puid });
  } catch (error) {
    console.error('Error in hiding psychologist profile:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/psychologistdetails', async (req, res) => {
  try {
    const { puid, name, gender, age, languages, area_of_expertise } = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('psychologists').doc(puid).set(
      {
        name, gender, age, languages, area_of_expertise
      },
      { merge: true } // This option ensures that existing data is not overwritten
    );

    res.json({ message: 'Psychologist details saved successfully', puid: puid });
  } catch (error) {
    console.error('Error in psychologist details registration step:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/registerPsychologistPhoneNumber', async (req, res) => {
  try {
    const { puid, phonenumber } = req.body;
    // Update user data in Firestore (add or update the nickname)
    await admin.firestore().collection('psychologists').doc(puid).set(
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
    await admin.firestore().collection('psychologists').doc(puid).set(
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

app.post('/psychologistLogin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Retrieve psychologist by email using the admin SDK
    const psychologistRecord = await admin.auth().getUserByEmail(email);
    if (psychologistRecord) {
      // Retrieve psychologist data from Firestore, assuming you have a 'psychologists' collection
      const psychologistDocRef = admin.firestore().collection('psychologists').doc(psychologistRecord.uid);
      const psychologistDoc = await psychologistDocRef.get();

      if (psychologistDoc.exists) {
        // Check if the psychologist has a nickname
        const storedHashedPassword = psychologistDoc.data().password;

        // Verify the entered password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, storedHashedPassword);

        if (isPasswordValid) {
          // Generate JWT token with psychologist UID and email
          const token = jwt.sign({ puid: psychologistRecord.uid, email: psychologistRecord.email }, 'atmanapplication');

          // Set the token in the psychologist document
          await psychologistDocRef.update({ token: token });

          // Include the token in the response header and respond with psychologist data
          res.header('Authorization', `Bearer ${token}`);
          res.json({
            message: 'Login successful',
            userData: { email: psychologistRecord.email, uid: psychologistRecord.uid, nickname: psychologistDoc.data().nickname, token: token },
          });
        } else {
          res.json({ message: 'Invalid email or password' });
        }
      } else {
        res.json({ message: 'Psychologist not found ' });
      }
    } else {
      res.json({ message: 'Psychologist not found' });
    }
  } catch (error) {
    console.error('Error during login:', error);

    // Handle specific authentication errors
    if (error.code === 'auth/user-not-found') {
      res.status(401).json({ message: 'Invalid email' });
    } else if (error.code === 'auth/wrong-password') {
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
app.post('/store-reminder', async (req, res) => {
  try {
    const { uid, time, date, plan } = req.body;

    // Create a reference to the reminders collection for the specific user and date
    const remindersCollectionRef = admin.firestore().collection('psychologists').doc(uid).collection('remainders').doc(date);

    // Check if the reminder already exists for the date
    const snapshot = await remindersCollectionRef.get();

    if (snapshot.exists) {
      // If reminders exist for the date, append the new reminder to the existing ones
      await remindersCollectionRef.update({
        reminders: admin.firestore.FieldValue.arrayUnion({ time, plan })
      });
    } else {
      // If no reminders exist for the date, create a new document and add the reminder
      await remindersCollectionRef.set({
        reminders: [{ time, plan }]
      });
    }

    res.json({ message: 'Reminder stored successfully' });
  } catch (error) {
    console.error('Error storing reminder:', error);
    res.status(500).json({ message: 'Internal Server Error' });
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

    const psychologistRef = admin.firestore().collection('psychologists').doc(puid);
    const [pendingAppointmentsSnapshot, approvedAppointmentsSnapshot, addedAppointmentsSnapshot] = await Promise.all([
      psychologistRef.collection("pending").doc("pending").get(),
      psychologistRef.collection("approved").doc("approved").get(),
      psychologistRef.collection("approved").doc("addedbyPsych").get(),
    ]);

    const pendingAppointmentsData = pendingAppointmentsSnapshot.data() || { bookings: [] };
    const approvedAppointmentsData = approvedAppointmentsSnapshot.data() || { bookings: [] };

    const fetchAppointmentDetails = async (appointments) => {
      return Promise.all(appointments.map(async (appointment) => {
        const userDetailsRef = admin.firestore().collection('users').doc("userDetails").collection("details").doc(appointment.uid);
        const userDetailsSnapshot = await userDetailsRef.get();
        const userDetails = userDetailsSnapshot.data();
        return { ...appointment, userDetails };
      }));
    };

    const [pendingAppointments, approvedAppointments] = await Promise.all([
      fetchAppointmentDetails(pendingAppointmentsData.bookings),
      fetchAppointmentDetails(approvedAppointmentsData.bookings)
    ]);

    // Fetch details for appointments added by psychologist
    const addedAppointmentsData = [];
    const uids = addedAppointmentsSnapshot.data().uids;
    for (const uid of uids) {
      const userDetailsRef = admin.firestore().collection('users').doc("userDetails").collection("details").doc(uid);
      const userDetailsSnapshot = await userDetailsRef.get();
      const userDetails = userDetailsSnapshot.data();
      const appointment = {uid: uid,}
      addedAppointmentsData.push({...appointment, userDetails});
    }

    res.json({
      pendingAppointments,
      approvedAppointments,
      addedAppointmentsData
    });
  } catch (error) {
    console.error('Error retrieving appointments:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




app.post('/addAppointmentToDoctorList', async (req, res) => {
  try {
    const { puid, nickname } = req.body;
console.log(puid, nickname);
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
      return res.json({ message: 'User with the provided nickname not found.' });
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
      return res.json({ message: 'Appointment with the same client already exists.' });
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



app.get('/api/messages', async (req, res) => {
  try {
    const messagesSnapshot = await admin.firestore().collection('messages').orderBy('timestamp').get();
    const messagesData = messagesSnapshot.docs.map((doc) => doc.data());
    res.json(messagesData);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const bucket = admin.storage().bucket();
app.post('/create-daily-picture', upload.single('image'), async (req, res) => {
  try {
    const { buffer } = req.file;

    // Upload the image to Firebase Storage
    const imageFilename = `${uuidv4()}.jpg`;
    const storageRef = admin.storage().bucket().file(imageFilename);
    await storageRef.save(buffer, { contentType: 'image/jpeg' });

    // Get the URL of the uploaded image
    const imageUrl = `https://firebasestorage.googleapis.com/v0/b/${storageRef.bucket.name}/o/${encodeURIComponent(imageFilename)}?alt=media`;

    // Get the reference to the dailyPictures document
    const dailyPicturesRef = admin.firestore().collection('users').doc('dailyPictures');

    // Get the current data of the dailyPictures document
    const dailyPicturesDoc = await dailyPicturesRef.get();
    let dailyPicturesData = dailyPicturesDoc.exists ? dailyPicturesDoc.data() : { pictures: [], currentIndex: 0 };

    // Ensure pictures field is initialized as an array
    if (!Array.isArray(dailyPicturesData.pictures)) {
      dailyPicturesData.pictures = [];
    }

    // Add the new picture to the pictures array with the index mapping
    const newPicture = { imageUrl };
    dailyPicturesData.pictures.push(newPicture);

    // Increment the currentIndex
    dailyPicturesData.currentIndex++;

    // Update the dailyPictures document in Firestore
    await dailyPicturesRef.set(dailyPicturesData);

    res.json({ message: 'Picture created successfully', picture: newPicture });
  } catch (error) {
    console.error('Error in create-daily-picture route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/fetch-daily-picture', async (req, res) => {
  try {
    // Get the reference to the dailyPictures document
    const dailyPicturesRef = admin.firestore().collection('users').doc('dailyPictures');

    // Get the current data of the dailyPictures document
    const dailyPicturesDoc = await dailyPicturesRef.get();
    const dailyPicturesData = dailyPicturesDoc.exists ? dailyPicturesDoc.data() : { pictures: [], currentIndex: 0 };

    // Ensure pictures field is initialized as an array
    if (!Array.isArray(dailyPicturesData.pictures)) {
      dailyPicturesData.pictures = [];
    }

    // Get the index of the next picture to fetch
    const nextIndex = dailyPicturesData.currentIndex;

    // Reset the index to 0 if all pictures have been fetched
    if (nextIndex >= dailyPicturesData.pictures.length) {
      dailyPicturesData.currentIndex = 0;
    }

    // Get the image URL at the next index
    const imageUrl = nextIndex < dailyPicturesData.pictures.length ?
      dailyPicturesData.pictures[nextIndex].imageUrl : null;

    res.json({ imageUrl });

    // Increment the currentIndex for the next fetch
    await dailyPicturesRef.update({ currentIndex: dailyPicturesData.currentIndex + 1 });
  } catch (error) {
    console.error('Error in fetch-daily-picture route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/create-post', upload.single('image'), async (req, res) => {
  try {
    const { title, description, uid } = req.body;
    const { buffer } = req.file;

    // Upload the image to Firebase Storage
    const imageFilename = `${uuidv4()}.jpg`;
    const storageRef = admin.storage().bucket().file(imageFilename);
    await storageRef.save(buffer, { contentType: 'image/jpeg' });

    // Get the URL of the uploaded image
    const imageUrl = `https://firebasestorage.googleapis.com/v0/b/${storageRef.bucket.name}/o/${encodeURIComponent(
      imageFilename
    )}?alt=media`;
    // Get the current date
    const currentDate = new Date();

    // Create a new post object
    const post = {
      uid,
      title,
      description,
      imageUrl,
      date: currentDate,
      likesCount: 0
    };

    // Reference to the "pending" subcollection under the "posts" document in the "users" collection
    const pendingPostsCollectionRef = admin.firestore().collection('users').doc('posts').collection('pending');

    // Add the new post document to the "pending" subcollection
    await pendingPostsCollectionRef.add(post);

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

app.get('/get-newsfeed', async (req, res) => {
  try {
    // Reference to the "approvedPosts" collection
    const postsCollectionRef = admin.firestore().collection('approvedPosts');

    // Retrieve the current posts data
    const postsQuerySnapshot = await postsCollectionRef.get();

    if (!postsQuerySnapshot.empty) {
      const postsData = [];
      const userDetailsPromises = []; // Array to hold promises for fetching user details

      postsQuerySnapshot.forEach(doc => {
        const postData = doc.data();
        const userDetailsPromise = admin.firestore().collection('users').doc("userDetails").collection("details").doc(postData?.uid).get();
        userDetailsPromises.push(userDetailsPromise);

        postsData.push({
          ...postData,
          id: doc.id // Add post ID to the post data
        });
      });

      // Wait for all user details promises to resolve
      const userDetailsSnapshots = await Promise.all(userDetailsPromises);

      // Merge user details into post data
      const mergedPostsData = postsData.map((postData, index) => ({
        ...postData,
        userDetails: userDetailsSnapshots[index].exists ? userDetailsSnapshots[index].data() : null
      }));

      // Check if any user details were not found in "details" collection
      const unresolvedUserDetailsIndices = userDetailsSnapshots.reduce((indices, snapshot, index) => {
        if (!snapshot.exists) {
          indices.push(index);
        }
        return indices;
      }, []);

      // Fetch user details from "psychologists" collection for unresolved user IDs
      const psychologistsPromises = unresolvedUserDetailsIndices.map(index => {
        const postData = mergedPostsData[index];
        return admin.firestore().collection('psychologists').doc(postData.uid).get();
      });

      // Wait for all psychologist details promises to resolve
      const psychologistsSnapshots = await Promise.all(psychologistsPromises);

      // Merge psychologist details into post data for unresolved user IDs
      psychologistsSnapshots.forEach((snapshot, index) => {
        const postData = mergedPostsData[unresolvedUserDetailsIndices[index]];
        if (snapshot.exists) {
          postData.userDetails = snapshot.data();
        }
      });

      // Sort posts by date in descending order
      const sortedPosts = mergedPostsData.sort((a, b) => b.date.toDate() - a.date.toDate());
      res.json({ posts: sortedPosts });
    } else {
      res.status(404).json({ message: 'No posts found' });
    }
  } catch (error) {
    console.error('Error in get-posts route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Define a route to handle file uploads
// app.post('/uploadaudio', upload.single('audio'), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).send('No file uploaded.');
//     }

//     const file = req.file;

//     // Create a reference to the file in Firebase Storage
//     const fileRef = bucket.file(file.originalname);

//     // Create a write stream to upload the file data
//     const uploadStream = fileRef.createWriteStream({
//       metadata: {
//         contentType: file.mimetype,
//       },
//     });

//     // Handle errors during the upload
//     uploadStream.on('error', (err) => {
//       console.error('Error uploading file:', err);
//       res.status(500).send('Error uploading file.');
//     });

//     // Handle successful upload
//     uploadStream.on('finish', async () => {
//       console.log('File uploaded successfully.');

//       // Get the URL of the uploaded audio file
//       const [url] = await fileRef.getSignedUrl({ action: 'read', expires: '01-01-2100' });

//       // Store the URL inside the users document
//       await admin.firestore().collection('users').doc('your_user_id').update({
//         audioUrl: url,
//       });

//       res.status(200).send('File uploaded successfully.');
//     });

//     // Pipe the file data to the write stream
//     uploadStream.end(file.buffer);
//   } catch (error) {
//     console.error('Error in uploadaudio route:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });


app.get('/getaudio/:filename', (req, res) => {
  const filename = req.params.filename;

  // Create a reference to the file in Firebase Storage
  const fileRef = bucket.file(filename);

  // Create a read stream to download the file data
  const downloadStream = fileRef.createReadStream();

  // Handle errors during the download
  downloadStream.on('error', (err) => {
    console.error('Error downloading file:', err);
    res.status(500).send('Error downloading file.');
  });

  // Set the appropriate content type for audio files
  res.set('Content-Type', 'audio/mpeg');

  // Pipe the file data to the response
  downloadStream.pipe(res);
});

app.post('/create-daily-picture', upload.single('image'), async (req, res) => {
  try {
    const { buffer } = req.file;

    // Upload the image to Firebase Storage
    const imageFilename = `${uuidv4()}.jpg`;
    const storageRef = admin.storage().bucket().file(imageFilename);
    await storageRef.save(buffer, { contentType: 'image/jpeg' });

    // Get the URL of the uploaded image
    const imageUrl = `https://firebasestorage.googleapis.com/v0/b/${storageRef.bucket.name}/o/${encodeURIComponent(
      imageFilename
    )}?alt=media`;

    // Get the current date
    const currentDate = new Date();

    // Create a new daily picture object
    const dailyPicture = {
      imageUrl,
      date: currentDate,
    };

    // Reference to the "daily_pictures" collection in the "users" collection
    const dailyPicturesRef = admin.firestore().collection('users').doc().collection('daily_pictures');

    // Add the new daily picture to the daily pictures collection
    await dailyPicturesRef.add(dailyPicture);

    res.json({ message: 'Daily picture created successfully' });
  } catch (error) {
    console.error('Error in create-daily-picture route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.post('/admin/postsStatus', async (req, res) => {
  try {
    // Reference to the "pending" subcollection
    const pendingPostsCollectionRef = admin.firestore().collection('users').doc('posts').collection('pending');

    // Retrieve all documents from the "pending" subcollection
    const pendingPostsSnapshot = await pendingPostsCollectionRef.get();

    // Array to hold post data with their document IDs
    const posts = [];

    // Process each document snapshot in the snapshot
    pendingPostsSnapshot.forEach(pendingPostDoc => {
      // Get the document data along with the document ID
      const postData = pendingPostDoc.data();

      // Add the document ID to the document data
      postData.docId = pendingPostDoc.id;

      // Add the document data to the array
      posts.push(postData);
    });

    res.status(200).json({ success: true, pendingPosts: posts });
    // res.status(200).json({ success: true, pendingPosts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});


app.post('/admin/approvepost', async (req, res) => {
  try {
    const { postId } = req.body;

    // Get the reference to the Firestore collections
    const pendingPostsCollectionRef = admin.firestore().collection('users').doc('posts').collection('pending');
    const approvedPostsCollectionRef = admin.firestore().collection('approvedPosts');

    // Retrieve the pending post
    const pendingPostDoc = await pendingPostsCollectionRef.doc(postId).get();

    // Check if the pending post exists
    if (pendingPostDoc.exists) {
      const pendingPostData = pendingPostDoc.data();

      // Add the pending post to the approved collection
      await approvedPostsCollectionRef.doc(postId).set({
        postId,
        ...pendingPostData,
      });

      // Delete the pending post
      await pendingPostDoc.ref.delete();

      res.status(200).json({ success: true, postId, message: 'Post approved and moved to the approved collection' });
    } else {
      res.status(404).json({ success: false, message: 'Pending post not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});



app.post('/admin/deletePost', async (req, res) => {
  try {
    const { postId } = req.body;

    // Get the reference to the Firestore collection
    const pendingPostsCollectionRef = admin.firestore().collection('users').doc('posts').collection('pending');

    // Retrieve the pending post
    const pendingPostDoc = await pendingPostsCollectionRef.doc(postId).get();

    // Check if the pending post exists
    if (pendingPostDoc.exists) {
      const pendingPostData = pendingPostDoc.data();

      // Check if the post is not approved
      if (!pendingPostData.approved) {
        // Delete the pending post
        await pendingPostDoc.ref.delete();


        res.status(200).json({ success: true, postId, message: 'Pending post deleted as it was not approved' });
      } else {
        res.status(400).json({ success: false, message: 'Pending post is already approved' });
      }
    } else {
      res.status(404).json({ success: false, message: 'Pending post not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/admin/users', async (req, res) => {
  try {
    const userDetailsCollectionRef = admin.firestore().collection('users').doc('userDetails').collection('details'); // Change to your collection name and path
    const userDetailsSnapshot = await userDetailsCollectionRef.get();
    const userDetails = [];
    userDetailsSnapshot.forEach(doc => {
      userDetails.push(doc.data());
    });

    res.status(200).json({ success: true, users: userDetails });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/admin/doctors', async (req, res) => {
  try {
    const userDetailsCollectionRef = admin.firestore().collection('psychologists'); // Change to your collection name and path
    const userDetailsSnapshot = await userDetailsCollectionRef.get();
    const userDetails = [];
    userDetailsSnapshot.forEach(doc => {
      const userData = doc.data();
      userData.uid = doc.id; // Add the document ID to the user data
      userDetails.push(userData);
    });

    res.status(200).json({ success: true, users: userDetails });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});


admin.firestore().settings({ ignoreUndefinedProperties: true });
const http = require('http');
const server = http.createServer(app);
const io = require("socket.io")(server, {
  allowRequest: (req, callback) => {
    // Assuming you want to allow all requests for simplicity
    // You might want to implement your own logic here
    callback(null, true);
  },
  cors: {
    origin: 'http://127.0.0.1:5501',
    methods: ['GET', 'POST'],
  }
});
function generateConversationId(userId1, userId2) {
  // Sort the user IDs to ensure consistency
  const sortedUserIds = [userId1, userId2].sort();

  // Concatenate the sorted user IDs to form the conversation ID
  return sortedUserIds.join('_');
}
const soketconnections = {}
io.on('connection', (socket) => {
  console.log('A user connected');

  socket.on('join', (data) => {
    soketconnections[data.sender] = socket.id;
    // You can also save the join event to Firestore if needed
    io.emit('joined', { soketconnections })

  });

  socket.on('newmessage', async (data) => {
    try {
      const conversationId = generateConversationId(data.sender, data.receiver);

      // Reference the Firestore document for the conversation
      const conversationRef = admin.firestore().collection('chat').doc(conversationId);

      // Check if the conversation document exists
      const conversationSnapshot = await conversationRef.get();
      const timestamp = Date.now();
      const newMessage = {
        sender: data.sender,
        text: data.text,
        timestamp: timestamp,
      };

      if (!conversationSnapshot.exists) {
        // If the document doesn't exist, create it with the initial message
        await conversationRef.set({
          messages: [newMessage],  // Start with an array containing the new message
        });
      } else {
        // If the document already exists, update it with the new message
        await conversationRef.update({
          messages: admin.firestore.FieldValue.arrayUnion(newMessage),
        });
      }
      io.to(soketconnections[data.receiver]).emit('newmessage', newMessage);
    } catch (error) {
      console.error('Error handling new message:', error);
    }
  });

  socket.on('getPreviousMessages', async (data) => {
    try {
      const conversationId = generateConversationId(data.sender, data.receiver);

      // Reference to the conversation document
      const conversationRef = admin.firestore().collection('chat').doc(conversationId);

      // Get the current messages array
      const conversationDoc = await conversationRef.get();
      const previousMessages = conversationDoc.data()?.messages || [];
      io.emit('previousmessages', previousMessages)

    } catch (error) {
      console.error('Error getting previous messages:', error);
    }
  });


  socket.on('newAnswer', (offerObj, ackFunction) => {
    console.log(offerObj);
    //emit this answer (offerObj) back to CLIENT1
    //in order to do that, we need CLIENT1's socketid
    const socketToAnswer = connectedSockets.find(s => s.userName === offerObj.offererUserName)
    if (!socketToAnswer) {
      console.log("No matching socket")
      return;
    }
    //we found the matching socket, so we can emit to it!
    const socketIdToAnswer = socketToAnswer.socketId;
    //we find the offer to update so we can emit it
    const offerToUpdate = offers.find(o => o.offererUserName === offerObj.offererUserName)
    if (!offerToUpdate) {
      console.log("No OfferToUpdate")
      return;
    }
    //send back to the answerer all the iceCandidates we have already collected
    ackFunction(offerToUpdate.offerIceCandidates);
    offerToUpdate.answer = offerObj.answer
    offerToUpdate.answererUserName = userName
    //socket has a .to() which allows emiting to a "room"
    //every socket has it's own room
    socket.to(socketIdToAnswer).emit('answerResponse', offerToUpdate)
  })

  socket.on('sendIceCandidateToSignalingServer', iceCandidateObj => {
    const { didIOffer, iceUserName, iceCandidate } = iceCandidateObj;
    // console.log(iceCandidate);
    if (didIOffer) {
      //this ice is coming from the offerer. Send to the answerer
      const offerInOffers = offers.find(o => o.offererUserName === iceUserName);
      if (offerInOffers) {
        offerInOffers.offerIceCandidates.push(iceCandidate)
        // 1. When the answerer answers, all existing ice candidates are sent
        // 2. Any candidates that come in after the offer has been answered, will be passed through
        if (offerInOffers.answererUserName) {
          //pass it through to the other socket
          const socketToSendTo = connectedSockets.find(s => s.userName === offerInOffers.answererUserName);
          if (socketToSendTo) {
            socket.to(socketToSendTo.socketId).emit('receivedIceCandidateFromServer', iceCandidate)
          } else {
            console.log("Ice candidate recieved but could not find answere")
          }
        }
      }
    } else {
      //this ice is coming from the answerer. Send to the offerer
      //pass it through to the other socket
      const offerInOffers = offers.find(o => o.answererUserName === iceUserName);
      const socketToSendTo = connectedSockets.find(s => s.userName === offerInOffers.offererUserName);
      if (socketToSendTo) {
        socket.to(socketToSendTo.socketId).emit('receivedIceCandidateFromServer', iceCandidate)
      } else {
        console.log("Ice candidate recieved but could not find offerer")
      }
    }
    // console.log(offers)
  })





  socket.on('disconnect', () => {
    console.log('User disconnected');

  });
});

app.post("/api/sendmessages", async (req, res) => {
  try {
    const { puid, uids, message } = req.body;

    // Iterate through each UID
    for (const uid of uids) {
      // Create the conversation ID by combining PUID and UID
      const conversationId = generateConversationId(uid, puid);
      console.log(conversationId);

      // Get the reference to the Firestore document using the conversationId
      const conversationRef = admin.firestore().collection('chat').doc(conversationId);
      const timestamp = Date.now();

      const newMessage = {
        sender: puid,
        text: message,
        timestamp: timestamp,
      };

      // Check if the document exists
      const doc = await conversationRef.get();
      if (!doc.exists) {
        // If the document doesn't exist, create it with the initial message
        await conversationRef.set({ messages: [newMessage] });
      } else {
        // If the document exists, update it by appending the new message to the 'messages' array
        await conversationRef.update({
          messages: admin.firestore.FieldValue.arrayUnion(newMessage)
        });
      }
    }
    res.status(200).json({ success: true, message: 'Messages sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post("/api/record", async (req, res) => {
  try {
    const { uid, puid, records } = req.body;

    // Get the reference to the Firestore document using the provided UID
    const userRecordRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid)
      .collection('records').doc('record'); // Make sure this document exists

    // Add timestamp to the document
    const timestamp = Date.now();

    // Update the document by appending the records to the 'records' array
    await userRecordRef.update({
      records: admin.firestore.FieldValue.arrayUnion({
        puid,
        timestamp,
        records
      })
    });

    res.status(200).json({ success: true, message: 'Records added successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});
app.get("/api/record/:uid", async (req, res) => {
  try {
    const { uid } = req.params;

    // Get the reference to the Firestore document using the provided UID
    const userRecordRef = admin.firestore().collection('users').doc('userDetails').collection('details').doc(uid)
      .collection('records').doc('record'); // Make sure this document exists

    // Retrieve the document data
    const docSnapshot = await userRecordRef.get();

    // Check if the document exists
    if (docSnapshot.exists) {
      const data = docSnapshot.data();
      res.status(200).json({ success: true, data });
    } else {
      res.status(404).json({ success: false, error: 'Document not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});
// Start the Express server
server.listen(3002, () => {
  console.log(`Server is running on port ${3002}`);
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`); ``
});
