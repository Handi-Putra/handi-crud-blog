require('dotenv').config();
const express = require('express');
const cors = require('cors');
const favicon = require('serve-favicon');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const mongoose = require('mongoose');
const validator = require('validator');
const fs = require('fs');

const jwtSecret = process.env.JWT_SECRET;
const app = express();
const PORT = process.env.PORT || 5500;

// Favicon Middleware
app.use((req, res, next) => {
  const faviconPath = path.join(__dirname, 'public', 'favicon.ico');
  if (fs.existsSync(faviconPath)) {
    app.use(favicon(faviconPath));
  }
  next();
});

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
};

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
  });
});

// MongoDB Models
const Post = mongoose.model(
  'Post',
  new mongoose.Schema({
    title: String,
    content: String,
    imageUrl: String,
    author: String,
    timestamp: String,
  })
);

const User = mongoose.model(
  'User',
  new mongoose.Schema({
    username: String,
    password: String,
    role: String,
  })
);

// Middleware
app.use(cors({ origin: '*' }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (token) {
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) {
        console.error('JWT Verification Error:', err.message);
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    console.error('Token is missing');
    res.sendStatus(401);
  }
};

// User registration
app.post('/index.html/register', async (req, res) => {
  const { username, password, role } = req.body;

  // Sanitize and validate user input
  if (!validator.isAlphanumeric(username) || !validator.isAlphanumeric(password) || !['admin', 'user'].includes(role)) {
    return res.status(400).send({ error: 'Invalid input data' });
  }

  const sanitizedUsername = validator.escape(username);
  const sanitizedPassword = validator.escape(password);

  try {
    const hashedPassword = await bcrypt.hash(sanitizedPassword, 10);

    const newUser = new User({
      username: sanitizedUsername,
      password: hashedPassword,
      role,
    });

    await newUser.save();
    res.status(201).send({ success: true });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Sanitize and validate user input
  if (!validator.isAlphanumeric(username) || !validator.isAlphanumeric(password)) {
    return res.status(400).send({ error: 'Invalid input data' });
  }

  const sanitizedUsername = validator.escape(username);
  const sanitizedPassword = validator.escape(password);

  try {
    const user = await User.findOne({ username: sanitizedUsername });

    if (user && await bcrypt.compare(password, user.password)) {
      const accessToken = jwt.sign(
        { username: user.username, role: user.role },
        jwtSecret,
        { expiresIn: '24h' }
      );
      res.status(200).send({ success: true, token: accessToken, role: user.role });
    } else {
      res.status(401).send({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// Fetch all posts
app.get('/posts', async (req, res) => {
  try {
    const posts = await Post.find();
    res.status(200).send(posts);
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// Create a new post
app.post('/posts', authenticateJWT, async (req, res) => {
  if (req.user.role === 'admin') {
    const { title, content, imageUrl, author, timestamp } = req.body;

    const newPost = new Post({
      title,
      content,
      imageUrl,
      author,
      timestamp,
    });

    try {
      const savedPost = await newPost.save();
      res.status(201).send(savedPost);
    } catch (error) {
      console.error('Error saving post:', error);
      res.status(500).send({ error: 'Internal Server Error' });
    }
  } else {
    res.sendStatus(403);
  }
});

// Fetch a single post
app.get('/post/:id', async (req, res) => {
  const postId = req.params.id;
  try {
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).send('Post not found');
    }

    // Read the HTML template from the file
    fs.readFile(path.join(__dirname, 'post-detail.html'), 'utf8', (err, data) => {
      if (err) {
        console.error('Error reading post detail HTML:', err);
        return res.status(500).send('Internal Server Error');
      }

      // Replace placeholders in the HTML with actual post data
      const postDetailHtml = data
        .replace(/\${post.imageUrl}/g, post.imageUrl)
        .replace(/\${post.title}/g, post.title)
        .replace(/\${post.timestamp}/g, post.timestamp)
        .replace(/\${post.author}/g, post.author)
        .replace(/\${post.content}/g, post.content);

      res.status(200).send(postDetailHtml);
    });
  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// Delete a post
app.delete('/posts/:id', authenticateJWT, async (req, res) => {
  if (req.user.role === 'admin') {
    try {
      await Post.findByIdAndDelete(req.params.id);
      res.status(200).send({ message: 'Post deleted' });
    } catch (error) {
      console.error('Error deleting post:', error);
      res.status(500).send({ error: 'Internal Server Error' });
    }
  } else {
    res.status(403).send({ error: 'Forbidden' });
  }
});

// Update a post
app.put('/posts/:id', authenticateJWT, async (req, res) => {
  const { title, content } = req.body;
  const postId = req.params.id;

  try {
    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).send({ error: 'Post not found' });
    }

    if (req.user.role === 'admin') {
      post.title = title;
      post.content = content;
      await post.save();
      res.status(200).send(post);
    } else {
      res.status(403).send({ error: 'Forbidden' });
    }
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});
