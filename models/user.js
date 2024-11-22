const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true
  },
  lastName: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/, 'Please fill a valid email address'] // اعتبارسنجی ایمیل
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'], // نقش‌های ممکن
    default: 'user',         // پیش‌فرض به عنوان کاربر
  },
  profileImage: {
    type: String,  // مسیر یا URL تصویر پروفایل
    default: ''    // پیش‌فرض خالی برای کاربرانی که تصویری ندارند
  }
}, { timestamps: true }); // برای ذخیره تاریخ ایجاد و بروزرسانی

// هش کردن پسورد قبل از ذخیره
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10); // هش کردن پسورد با bcrypt
  }
  next();
});

// جلوگیری از تعریف مجدد مدل
module.exports = mongoose.models.User || mongoose.model('User', userSchema);
