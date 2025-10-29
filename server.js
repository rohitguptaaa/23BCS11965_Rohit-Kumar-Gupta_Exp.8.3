require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;

// --- Sample users ---
const USERS = [
  { id: 1, username: 'adminUser', password: 'admin123', role: 'Admin' },
  { id: 2, username: 'modUser', password: 'mod123', role: 'Moderator' },
  { id: 3, username: 'normalUser', password: 'user123', role: 'User' }
];

// Generate JWT
function generateToken(user) {
  const payload = { id: user.id, username: user.username, role: user.role };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Routes
app.get('/', (req, res) => {
  res.send('Exp.8.3 — JWT Role-Based Authentication is Running');
});

// Login Route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = generateToken(user);
  res.json({ token });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ message: 'Token missing' });

  const token = header.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
}

// Role-based Access Middleware
function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: insufficient role' });
    }
    next();
  };
}

// Admin Dashboard
app.get('/admin-dashboard', verifyToken, allowRoles('Admin'), (req, res) => {
  res.json({
    message: 'Welcome to the Admin dashboard',
    user: req.user
  });
});

// Moderator Panel
app.get('/moderator-panel', verifyToken, allowRoles('Moderator'), (req, res) => {
  res.json({
    message: 'Welcome to the Moderator panel',
    user: req.user
  });
});

// User Profile
app.get('/user-profile', verifyToken, (req, res) => {
  res.json({
    message: `Welcome to your profile, ${req.user.username}`,
    user: req.user
  });
});

app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
