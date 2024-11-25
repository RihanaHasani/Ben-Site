if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();  // بارگذاری متغیرهای محیطی از فایل .env
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require('./models/user');
const initializePassport = require('./passport-config'); 
const multer = require('multer');
const path = require('path');

// پیکربندی Passport
initializePassport(passport);

// استفاده از express-session پیش از Passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// استفاده از Passport برای شناسایی کاربر
app.use(passport.initialize());
app.use(passport.session());

// Middleware برای بررسی نقش کاربر
function checkRole(role) {
  return (req, res, next) => {
    if (req.isAuthenticated()) {
      if (req.user.role === role) {
        return next();
      } else {
        return res.status(403).send('Forbidden'); // دسترسی ممنوع برای کسانی که نقش صحیح را ندارند
      }
    }
    res.redirect('/login'); // اگر کاربر وارد نشده باشد
  };
}

// تنظیمات اولیه
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: false }));



// اتصال به MongoDB atlas

const uri = process.env.DB_URI;

mongoose.connect(process.env.DB_URI, {
  ssl: true,
})
.then(() => {
  console.log('Connected to MongoDB!');
})
.catch((err) => {
  console.error('Error connecting to MongoDB:', err);
});





// سایر تنظیمات Passport و Session
app.use(flash());
app.use(methodOverride('_method'));
// مسیر استاتیک برای فولدر uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// صفحه اصلی همیشه باید نمایش داده شود، چه کاربر وارد شده باشد و چه نه
app.get('/', (req, res) => {
  res.render('index.ejs', { user: req.user }); // همیشه صفحه اصلی نمایش داده می‌شود
});




// روت‌ها
app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { user: req.user });
});

app.get('/admin', checkAuthenticated, checkRole('admin'), (req, res) => {
  res.render('admin-dashboard.ejs', { user: req.user });
});

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const { firstName, lastName, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role: role || 'user', // نقش به صورت پیش‌فرض 'user'
    });
    await newUser.save();
    res.redirect('/login');
  } catch (e) {
    console.error(e);
    res.status(500).send("Error registering user");
  }
});

app.get('/dashboard', checkAuthenticated, (req, res) => {
  if (req.user.role === 'admin') {
    return res.render('admin-dashboard.ejs', { user: req.user });
  } else {
    return res.render('user-dashboard.ejs', { user: req.user });
  }
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}



// تنظیمات Multer برای ذخیره‌سازی تصاویر
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads'); // مسیر ذخیره‌سازی فایل‌ها
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // نام فایل با استفاده از زمان جاری و پسوند فایل
  }
});

// فقط اجازه آپلود فایل‌های تصویری را بدهید
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb('Error: Only image files are allowed!');
    }
  }
});

app.post('/upload-profile-image', checkAuthenticated, upload.single('profileImage'), async (req, res) => {
  if (req.file) {
    const profileImagePath = `public/uploads/${req.file.filename}`;

    try {
      // به‌روزرسانی مسیر تصویر پروفایل در دیتابیس
      const updatedUser = await User.findByIdAndUpdate(
        req.user._id, 
        { profileImage: profileImagePath },
        { new: true }
      );

      // هدایت کاربر به داشبورد
      res.redirect('/dashboard');
    } catch (err) {
      console.error('Error updating profile image:', err);
      return res.status(500).send('Error updating profile image');
    }
  } else {
    res.status(400).send('No file uploaded');
  }
});


app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});



