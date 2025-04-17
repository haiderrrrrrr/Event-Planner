require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/eventPlanner')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true }
}));

User.schema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const Event = mongoose.model('Event', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  description: String,
  date: { type: Date, required: true },
  category: { type: String, enum: ['Meeting', 'Birthday', 'Appointment', 'Other'], default: 'Other' },
  reminder: Date
}));

const authenticate = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Authorization required' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

cron.schedule('* * * * *', async () => {
  const events = await Event.find({ reminder: { $lte: new Date() }, notified: false });
  events.forEach(async event => {
    await transporter.sendMail({
      to: (await User.findById(event.userId)).email,
      subject: `Reminder: ${event.name}`,
      text: `Your event "${event.name}" is coming up!`
    });
    event.notified = true;
    await event.save();
  });
});

app.post('/auth/register', [
  body('username').notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ message: 'Registration failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '1h' });
  res.json({ token });
});

app.post('/events', authenticate, [
  body('name').notEmpty(),
  body('date').isISO8601()
], async (req, res) => {
  const event = new Event({ userId: req.user.userId, ...req.body });
  await event.save();
  res.status(201).json(event);
});

app.get('/events', authenticate, async (req, res) => {
  const events = await Event.find({ userId: req.user.userId }).sort(req.query.sort || 'date');
  res.json(events);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));