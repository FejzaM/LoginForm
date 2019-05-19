const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require ('passport');

//User Model
const User = require ('../models/User');

//Login Page
router.get('/login', (_req, res) => res.render('login'));

//Regsiter Page
router.get('/register', (req, res) => res.render('register'));

//Register Handle
router.post('/register', (req,res) => {
   const { name, email, password, password2 } = req.body;
   let errors = [];

   //Check required fields
   if (!name || !email || !password || !password2) {
       errors.push({ msg: "Please Fill In All Fields"});
   }
   //Check password match
   if(password !== password2) {
       errors.push({ msg: "Passwords Do Not Match"});
   }

   //Check pass length
   if(password.length <6) {
       errors.push({ msg: "Password Must Be Least 6 Characters"});
   }

   if(errors.length > 0) {
       res.render('register',{
           errors,
           name,
           email,
           password,
           password2
       });
   } else {
       // Validation Passed
    User.findOne({ email: email})
    .then(user => {
        if(user) {
            //user exists
            errors.push({ msg: 'Email Is Already Registered'});
            res.render('register',{
                errors,
                name,
                email,
                password,
                password2
            });
        } else {
           const newUser = new User ({
             name,
             email,
             password
           }); 
           // Hash Password
           bcrypt.genSalt(10, (err, salt) =>
           bcrypt.hash(newUser.password, salt, (err, hash) => {
               if (err) throw err;
               //Set password for hashed
               newUser.password = hash;
               //Save user 
               newUser.save()
               .then(user => {
                   req.flash('success_msg', 'You are now registered and can log in');
                   res.redirect('/users/login');
               })
               .catch(err => console.log(err));
           }))
        }
    });
   }
});

// Login Handle
router.post('/login', (req, res, next) =>{
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

//Logout Handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
});

module.exports = router;