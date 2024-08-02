require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

const server = http.createServer(app);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET;

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  address: String,
  city: String,
  postalCode: String,
  country: String,
  orders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }],
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: Date,
  totalPrice: Number,
  completed: Boolean,
  deliveryDate: Date,
  products: Array,
  status: { type: String, enum: ['Pending', 'Confirmed', 'Delivered'], default: 'Pending' }
});

const Order = mongoose.model('Order', orderSchema);

// SSE setup
let clients = [];

app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  clients.push(res);

  req.on('close', () => {
    clients = clients.filter(client => client !== res);
  });
});

const notifyAllClients = (message, userId = null) => {
  const notification = { message, userId };
  clients.forEach(client => client.write(`data: ${JSON.stringify(notification)}\n\n`));
};

// Register Route
app.post('/api/users/signup', async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'user'
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Logout Route
app.post('/logout', (req, res) => {
  res.status(200).json({ message: 'Logout successful' });
});

// Middleware to authenticate JWT token
const authenticateToken = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;

    const user = await User.findById(req.userId, 'role');
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Middleware to check for admin role
const authenticateAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Access forbidden: Admins only' });
  }
  next();
};

// Endpoint to create admin users (protected)
app.post('/api/admin/signup', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: 'admin'
    });

    await user.save();
    res.status(201).json({ message: 'Admin registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Current User
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API Routes
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const userRole = req.userRole;

    let orders;
    if (userRole === 'admin') {
      orders = await Order.find().populate('userId');
    } else {
      orders = await Order.find({ userId }).populate('userId');
    }

    if (!orders.length) {
      return res.status(404).json({ message: 'No orders found' });
    }

    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/users', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find().populate('orders');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/orders/:id/confirm', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { deliveryDate } = req.body;

  try {
    const order = await Order.findOne({ _id: id }).populate('userId');
    if (order) {
      order.completed = true;
      order.deliveryDate = deliveryDate;
      order.status = 'Confirmed';
      await order.save();

      notifyAllClients('Order confirmed', order.userId._id);  // Include userId in notification
      res.json(order);
    } else {
      res.status(404).json({ message: 'Order not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deliver an Order
app.post('/orders/:orderId/deliver', authenticateToken, authenticateAdmin, async (req, res) => {
  const { orderId } = req.params;

  try {
    const order = await Order.findById(orderId).populate('userId');
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    order.status = 'Delivered';
    await order.save();

    notifyAllClients('Order delivered', order.userId._id);  // Include userId in notification
    res.status(200).json({ message: 'Order delivered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error delivering order' });
  }
});

// Create an Order
app.post('/orders', authenticateToken, async (req, res) => {
  const { date, totalPrice, products } = req.body;
  const userId = req.userId;

  try {
    const order = new Order({
      userId,
      date,
      totalPrice,
      products,
      completed: false,
      status: 'Pending'
    });

    const savedOrder = await order.save();

    const user = await User.findById(userId);
    user.orders.push(savedOrder._id);
    await user.save();

    notifyAllClients('New order placed', userId);
    res.status(201).json(savedOrder);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Orders
app.get('/orders/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;

  try {
    const orders = await Order.find({ userId }).populate('userId');
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start the server
server.listen(process.env.PORT, () => {
  console.log(`Server  running on port ${process.env.PORT}`);
});
