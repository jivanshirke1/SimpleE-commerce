const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost/ecommerce', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Schemas & Models
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
});

const ProductSchema = new mongoose.Schema({
  name: String,
  category: String,
  price: Number,
});

const CartSchema = new mongoose.Schema({
  userId: String,
  items: [{ productId: String, quantity: Number }],
});

const OrderSchema = new mongoose.Schema({
  userId: String,
  items: [{ productId: String, quantity: Number }],
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Cart = mongoose.model('Cart', CartSchema);
const Order = mongoose.model('Order', OrderSchema);

// Middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, 'secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.sendStatus(403);
    next();
  };
}

// Auth Routes
app.post('/register', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new User({ ...req.body, password: hashedPassword });
  await user.save();
  res.sendStatus(201);
});

app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(403).send('Invalid credentials');
  }
  const token = jwt.sign({ id: user._id, role: user.role }, 'secret');
  res.json({ token });
});

// Product Routes
app.get('/products', async (req, res) => {
  const { page = 1, limit = 10, search = '', category = '' } = req.query;
  const query = {
    name: { $regex: search, $options: 'i' },
    category: { $regex: category, $options: 'i' },
  };
  const products = await Product.find(query)
    .limit(limit * 1)
    .skip((page - 1) * limit);
  res.json(products);
});

app.post('/products', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.sendStatus(201);
});

app.put('/products/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  await Product.findByIdAndUpdate(req.params.id, req.body);
  res.sendStatus(200);
});

app.delete('/products/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

// Cart Routes
app.get('/cart', authenticateToken, async (req, res) => {
  const cart = await Cart.findOne({ userId: req.user.id });
  res.json(cart || { items: [] });
});

app.post('/cart', authenticateToken, async (req, res) => {
  let cart = await Cart.findOne({ userId: req.user.id });
  if (!cart) cart = new Cart({ userId: req.user.id, items: [] });
  cart.items.push(req.body);
  await cart.save();
  res.sendStatus(201);
});

app.put('/cart', authenticateToken, async (req, res) => {
  await Cart.findOneAndUpdate({ userId: req.user.id }, { items: req.body.items });
  res.sendStatus(200);
});

app.delete('/cart', authenticateToken, async (req, res) => {
  await Cart.findOneAndDelete({ userId: req.user.id });
  res.sendStatus(204);
});

// Order Routes
app.post('/order', authenticateToken, async (req, res) => {
  const cart = await Cart.findOne({ userId: req.user.id });
  if (!cart || cart.items.length === 0) return res.status(400).send('Cart is empty');
  const order = new Order({ userId: req.user.id, items: cart.items });
  await order.save();
  await Cart.findOneAndDelete({ userId: req.user.id });
  res.sendStatus(201);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
