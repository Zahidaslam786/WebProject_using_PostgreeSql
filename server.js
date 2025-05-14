const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files (frontend)
app.use(express.static('public'));

// PostgreSQL Connection
const pool = new Pool({
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
  port: 5432,
});

pool.connect()
  .then(() => console.log('PostgreSQL connected'))
  .catch(err => console.error('PostgreSQL connection error:', err));

// Enhanced error handling for database connection
pool.on('error', (err) => {
  console.error('Unexpected database error:', err);
});

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com', // Gmail SMTP server
  port: 587, // Use port 587 for TLS
  secure: false, // Set to false for TLS
  auth: {
    user: process.env.GMAIL_USER, // Gmail address
    pass: process.env.GMAIL_PASS, // App Password
  },
});

// Test email configuration
transporter.verify((error, success) => {
  if (error) {
    console.error('SMTP server connection error:', error);
  } else {
    console.log('SMTP server is ready to send emails');
  }
});

// Email Templates
const sendWelcomeEmail = async (to, name) => {
  try {
    const info = await transporter.sendMail({
      from: `"Home Service Hub" <${process.env.GMAIL_USER}>`,
      to,
      subject: 'Welcome to Home Service Hub!',
      html: `
        <h2>Welcome, ${name}!</h2>
        <p>Thank you for joining Home Service Hub, your trusted partner for home services in Pakistan.</p>
        <p>Book verified professionals for plumbing, electrical work, cleaning, and more.</p>
        <a href="http://localhost:3000/index.html" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 8px; display: inline-block;">Explore Services</a>
        <p>Best regards,<br>Home Service Hub Team</p>
      `,
    });
    console.log(`Welcome email sent to ${to}: ${info.messageId}`);
  } catch (error) {
    console.error(`Failed to send welcome email to ${to}:`, error);
  }
};

const sendLoginEmail = async (to, name) => {
  try {
    const info = await transporter.sendMail({
      from: `"Home Service Hub" <${process.env.GMAIL_USER}>`,
      to,
      subject: 'Successful Login to Home Service Hub',
      html: `
        <h2>Hello, ${name}!</h2>
        <p>You have successfully logged into your Home Service Hub account.</p>
        <p>Access your dashboard to view bookings and personalized offers.</p>
        <a href="http://localhost:3000/dashboard.html" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 8px; display: inline-block;">Go to Dashboard</a>
        <p>If this wasn't you, please reset your password immediately.</p>
        <p>Best regards,<br>Home Service Hub Team</p>
      `,
    });
    console.log(`Login email sent to ${to}: ${info.messageId}`);
  } catch (error) {
    console.error(`Failed to send login email to ${to}:`, error);
  }
};

const sendOtpEmail = async (to, otp) => {
  try {
    const info = await transporter.sendMail({
      from: `"Home Service Hub" <${process.env.GMAIL_USER}>`,
      to,
      subject: 'Password Reset OTP - Home Service Hub',
      html: `
        <h2>Password Reset Request</h2>
        <p>Your OTP for password reset is: <strong>${otp}</strong></p>
        <p>This OTP is valid for 10 minutes. Please use it to reset your password.</p>
        <p>If you did not request this, ignore this email.</p>
        <p>Best regards,<br>Home Service Hub Team</p>
      `,
    });
    console.log(`OTP email sent to ${to}: ${info.messageId}`);
  } catch (error) {
    console.error(`Failed to send OTP email to ${to}:`, error);
  }
};

// Middleware to validate email format
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return false;
  }

  const domain = email.split('@')[1].toLowerCase();
  const allowedDomains = ["gmail.com", "outlook.com", "yahoo.com", "cfd.nu.edu.pk"];
  return allowedDomains.includes(domain);
};

// Add this middleware function for token verification
const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  
  if (!bearerHeader) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    const decoded = jwt.verify(bearerToken, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Start a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [email]);
      if (existingUser.rows.length > 0) {
        throw new Error('Email already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await client.query(
        'INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name',
        [email, hashedPassword, name]
      );

      await sendWelcomeEmail(email, name);
      await client.query('COMMIT');
      
      res.status(201).json({ 
        message: 'User created successfully. Please check your email.',
        user: result.rows[0]
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Signup error:', error);
    res.status(error.message === 'Email already exists' ? 400 : 500)
       .json({ error: error.message || 'Server error during signup' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Send login notification email
    try {
      await sendLoginEmail(user.email, user.name);
    } catch (emailError) {
      console.error('Login email notification failed:', emailError);
      // Continue with login process even if email fails
    }

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Check Auth
app.get('/api/auth/check-auth', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.json({ success: false });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT id, email, name FROM users WHERE id = $1', [decoded.userId]);
    const user = result.rows[0];

    if (!user) {
      return res.json({ success: false });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error('Check auth error:', error);
    res.json({ success: false });
  }
});

// Send OTP for Password Reset
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Email not found' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await pool.query(
      'UPDATE users SET reset_otp = $1, reset_otp_expires = $2 WHERE email = $3',
      [otp, expires, email]
    );

    await sendOtpEmail(email, otp);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify OTP and Reset Password
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND reset_otp = $2 AND reset_otp_expires > $3',
      [email, otp, new Date()]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password = $1, reset_otp = NULL, reset_otp_expires = NULL WHERE email = $2',
      [hashedPassword, email]
    );

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invite', async (req, res) => {
  try {
    const { friendEmail } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    await transporter.sendMail({
      from: '"Home Service Hub" <' + process.env.GMAIL_USER + '>',
      to: friendEmail,
      subject: 'Join Home Service Hub!',
      html: `<p>You've been invited by ${user.name} to join Home Service Hub! <a href="http://localhost:3000/auth.html?mode=signup">Sign up now</a>.</p>`
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Invite error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout (for compatibility with index.html)
app.post('/api/auth/logout', (req, res) => {
  res.json({ success: true });
});

// Use this middleware in your protected routes
app.get('/protected-route', verifyToken, (req, res) => {
  // Your route logic here
});

// Mock user data (replace with database logic)
const users = [
  { email: 'test@example.com', password: 'Test@1234', name: 'Test User' },
];

// Login route
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  // Find user
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  // Generate JWT token
  const token = jwt.sign({ email: user.email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1h' });

  // Send token to frontend
  res.json({ token });
});

// Protected route example
app.get('/api/dashboard', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access Denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid Token' });

    res.json({ message: `Welcome ${user.name}!` });
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Example function to send an email
async function sendEmail(to, subject, text) {
  try {
    const info = await transporter.sendMail({
      from: `"Home Service Hub" <${process.env.GMAIL_USER}>`, // Sender address
      to, // List of recipients
      subject, // Subject line
      text, // Plain text body
    });
    console.log('Email sent: %s', info.messageId);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

// Example usage
sendEmail('recipient@example.com', 'Test Email', 'This is a test email from Home Service Hub.');