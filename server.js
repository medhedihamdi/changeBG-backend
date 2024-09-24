require('dotenv').config(); // تحميل متغيرات البيئة
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();

app.use(express.json());
app.use(cors());

// الاتصال بقاعدة بيانات MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB', err));

// تعريف نموذج المستخدم
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'user' },
    permissions: { type: [String], default: [] }
});

const User = mongoose.model('User', userSchema);

// إعداد مستخدم أدمن
const createAdminUser = async () => {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('123', 10);
        const adminUser = new User({ username: 'admin', password: hashedPassword, role: 'admin' });
        await adminUser.save();
        console.log('Admin user created');
    }
};

createAdminUser();

// Middleware للتحقق من التوكن
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(403).json({ message: 'Token missing' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const userExist = await User.findOne({ username });
    if (userExist) {
        return res.status(400).send("This user already exists");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    const token = jwt.sign({ username, role: 'user', permissions: [] }, process.env.SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// تسجيل الدخول
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(401).send("This user does not exist");
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).send("Incorrect password");
    }
    const token = jwt.sign({ username, role: user.role, permissions: user.permissions }, process.env.SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// الصفحة المحمية
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'Welcome to the protected page', user: req.user });
});

// لوحة التحكم للأدمن
app.get('/admin/dashboard', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    const users = await User.find();
    res.json({ message: 'Welcome to the admin dashboard', users });
});

// تفويض المستخدمين
app.post('/admin/authorize', verifyToken, async (req, res) => {
    const { username } = req.body;
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    user.permissions.push('changeBackground');
    await user.save();
    res.json({ message: 'User authorized' });
});

// تشغيل السيرفر
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
