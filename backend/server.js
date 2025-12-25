const express = require('express');
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ============ MIDDLEWARE ============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ============ MONGODB CONNECTION ============
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB Error:", err));

// ============ SCHEMAS ============
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  address: String,
  password: String,
  role: { type: String, enum: ['buyer', 'farmer'], default: 'buyer' },
  createdAt: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  unit: String,
  quantity: Number,
  category: String,
  description: String,
  image: String,
  farmerId: mongoose.Schema.Types.ObjectId,
  farmerName: String,
  farmerContact: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  items: [{
    name: String,
    price: Number,
    quantity: Number,
    image: String
  }],
  total: Number,
  status: { type: String, enum: ['pending', 'confirmed', 'out_for_delivery', 'delivered'], default: 'pending' },
  deliveryAddress: String,
  paymentMethod: String,
  createdAt: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  expiresAt: Date,
  createdAt: { type: Date, default: Date.now, expires: 300 } // Auto-delete after 5 mins
});

// ============ MODELS ============
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const OTP = mongoose.model('OTP', otpSchema);

// ============ HELPER FUNCTIONS ============
const generateJWT = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

const verifyJWT = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Middleware to verify token
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  const decoded = verifyJWT(token);
  if (!decoded) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
  req.userId = decoded.userId;
  next();
};

// ============ AUTH ENDPOINTS ============

// SIGNUP
app.post('/signup', async (req, res) => {
  try {
    const { name, email, phone, address, password, role } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);
    const newUser = new User({
      name,
      email,
      phone,
      address,
      password: hashedPassword,
      role: role || 'buyer'
    });

    await newUser.save();
    const token = generateJWT(newUser._id);

    res.status(201).json({
      success: true,
      message: 'Signup successful',
      token,
      user: { id: newUser._id, name, email, phone, address }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcryptjs.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const token = generateJWT(user._id);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email, phone: user.phone, address: user.address }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ PRODUCT ENDPOINTS ============

// SUBMIT PRODUCT (Farmer)
app.post('/api/products', authMiddleware, async (req, res) => {
  try {
    const { name, price, unit, quantity, category, description, image, farmerContact } = req.body;

    const newProduct = new Product({
      name,
      price,
      unit,
      quantity,
      category,
      description,
      image,
      farmerId: req.userId,
      farmerContact,
      status: 'pending'
    });

    await newProduct.save();

    res.status(201).json({
      success: true,
      message: 'Product submitted for approval',
      product: newProduct
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error submitting product' });
  }
});

// GET ALL APPROVED PRODUCTS
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ status: 'approved' });
    res.json({ success: true, products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching products' });
  }
});

// GET PENDING PRODUCTS (Admin)
app.get('/api/admin/pending-products', authMiddleware, async (req, res) => {
  try {
    const products = await Product.find({ status: 'pending' });
    res.json({ success: true, products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching pending products' });
  }
});

// APPROVE PRODUCT (Admin)
app.put('/api/admin/products/:id/approve', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { status: 'approved' },
      { new: true }
    );
    res.json({ success: true, message: 'Product approved', product });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error approving product' });
  }
});

// REJECT PRODUCT (Admin)
app.put('/api/admin/products/:id/reject', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { status: 'rejected' },
      { new: true }
    );
    res.json({ success: true, message: 'Product rejected', product });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error rejecting product' });
  }
});

// ============ ORDER ENDPOINTS ============

// CREATE ORDER
app.post('/api/orders', authMiddleware, async (req, res) => {
  try {
    const { items, total, deliveryAddress, paymentMethod } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ success: false, message: 'Cart is empty' });
    }

    const newOrder = new Order({
      userId: req.userId,
      items,
      total,
      deliveryAddress,
      paymentMethod,
      status: 'confirmed'
    });

    await newOrder.save();

    res.status(201).json({
      success: true,
      message: 'Order placed successfully',
      order: newOrder
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error creating order' });
  }
});

// GET USER ORDERS
app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching orders' });
  }
});

// GET ORDER BY ID
app.get('/api/orders/:id', authMiddleware, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }
    res.json({ success: true, order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching order' });
  }
});

// UPDATE ORDER STATUS
app.put('/api/orders/:id/status', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    res.json({ success: true, message: 'Order status updated', order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error updating order' });
  }
});

// ============ OTP ENDPOINTS ============

// SEND OTP
app.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email required' });
    }

    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    await OTP.deleteMany({ email }); // Clear old OTPs
    const newOTP = new OTP({ email, otp, expiresAt });
    await newOTP.save();

    // In production, send via email service (SendGrid, Nodemailer, etc.)
    console.log(`OTP for ${email}: ${otp}`);

    res.json({
      success: true,
      message: 'OTP sent successfully',
      testOTP: otp // Remove in production
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error sending OTP' });
  }
});

// VERIFY OTP
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and OTP required' });
    }

    const otpRecord = await OTP.findOne({ email, otp });
    if (!otpRecord) {
      return res.status(401).json({ success: false, message: 'Invalid OTP' });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(401).json({ success: false, message: 'OTP expired' });
    }

    await OTP.deleteOne({ _id: otpRecord._id });

    res.json({
      success: true,
      message: 'OTP verified successfully',
      resetToken: generateJWT(email) // Token for password reset
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error verifying OTP' });
  }
});

// ============ PROFILE ENDPOINTS ============

// GET USER PROFILE
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching profile' });
  }
});

// UPDATE USER PROFILE
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { name, phone, address } = req.body;
    const user = await User.findByIdAndUpdate(
      req.userId,
      { name, phone, address },
      { new: true }
    ).select('-password');
    res.json({ success: true, message: 'Profile updated', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error updating profile' });
  }
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Server error' });
});

// ============ START SERVER ============
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});