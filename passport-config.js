const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');  // وارد کردن bcrypt
const User = require('./models/user');  // مدل کاربر

function initialize(passport) {
  passport.use(new LocalStrategy({
    usernameField: 'email',  // ایمیل به عنوان نام کاربری
    passwordField: 'password'  // رمز عبور
  }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email }); // جستجو برای کاربر
      if (!user) {
        return done(null, false, { message: 'No user with that email' });
      }

      // مقایسه رمز عبور هش‌شده
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password' });
      }
    } catch (error) {
      return done(error);
    }
  }));

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
}

module.exports = initialize;
