var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var passport = require('passport');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jwt-simple');
const bodyParser = require('body-parser');


router.use(bodyParser.urlencoded({ extended: false }));

/* GET home page. */
router.get('/', (req, res) => {
  console.log(" / " + req.user);
  console.log("This is the value of authentuntication = " +req.isAuthenticated());
  res.render('home', {
    title: 'Home'
  });
});

router.get('/profile/', authenticationMiddleware(),(req, res, next) => {
  //console.log("router.get/profile/ : "+ req.user.user_id);
  //res.render('profile',{title:'Profile'});
  var userId = req.user.user_id;
  console.log(userId);
  var db = require('../db.js');
  db.query('SELECT * FROM users where id = ?',[userId], (err,results,fields)=>{
    if(err) {
      console.log("Error occured while getting the user detail of " + userId, err);
    }
    else{
      res.render('profile',{title:'Profile',user_detail:results[0]});
      //console.log(results[0]);
    }
    
  });
});

//For login

router.get('/login', (req,res)=>{
  res.render('login',{title:'login'});
});

router.post('/login', passport.authenticate('local', {
  successRedirect:'/profile/',
  failureRedirect:'/login/'
}));

//for logout

router.get('/logout', (req,res)=>{
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

//for forgot password

router.get('/forgot', function(req, res) {
  res.render('forgot',{title:'Password Reset'});
});

router.post('/forgot',(req,res)=>{
  var db = require('../db.js');
  if (req.body.email !== undefined) {
    var emailAddress = req.body.email;
   
    // TODO: Using email, find user from your database.
    db.query('SELECT * FROM users WHERE email = ?',[emailAddress],(err,results,fields)=>{
      if(err){
        console.log('Error in pulling the information of the user from the database');
      }
      //console.log(results[0].id);
      else{
        var  userid = results[0].id;
        var userpassword = results[0].password;
        var userregdate = results[0].regdate;
        var date = new Date(userregdate);
        console.log(date);
      }
   

    var payload = {
        id: userid,        // User ID from database
        email: emailAddress
    }
    console.log(payload);
  
    // TODO: Make this a one-time-use token by using the user's
    // current password hash from the database, and combine it
    // with the user's created date to make a very unique secret key!
    // For example:
    var secret = userpassword + '-' + date.getTime();
    //var secret = 'fe1a1915a379f3be5394b64d14794932-1506868106675';
    console.log(secret);
    var token = jwt.encode(payload, secret);
    console.log(token);
    // TODO: Send email containing link to reset password.
    // In our case, will just return a link to click.
    res.send('<a href="/resetpassword/' + payload.id + '/' + token + '">Reset password</a>');
    
  });
  } else {
    res.send('Email address is missing.');
}
});

// Reseeting the password 

router.get('/resetpassword/:id/:token', function(req, res) {
  // TODO: Fetch user from database using
  // req.params.id
  console.log('My user id  is '+ req.params.id);
  //console.log('My token is '+ req.params.token);
  //var Token = req.params.token;
  var db = require('../db.js');
  db.query('SELECT * FROM users WHERE id = ?',[req.params.id],(err,results,fields)=>{
    if(err){
      console.log('Error in reseting the password of the' + req.params.id);
    }
    //console.log(results[0].id);
    else{
    var date = new Date(results[0].regdate);
    var secret = results[0].password + '-' + date.getTime();
    }
    //console.log(secret);
    //console.log(Token);
    var payload = jwt.decode(req.params.token, secret);
    
  // TODO: Decrypt one-time-use token using the user's
  // current password hash from the database and combine it
  // with the user's created date to make a very unique secret key!
  // For example,
  // var secret = user.password + ‘-' + user.created.getTime();
  //var secret = 'fe1a1915a379f3be5394b64d14794932-1506868106675';
  //var payload = jwt.decode(req.params.token, secret);

  // TODO: Gracefully handle decoding issues.
  // Create form to reset password.
    res.send('/header'+'<form action="/resetpassword" method="POST">' +
    '<input type="hidden" name="id" value="' + payload.id + '" />' +
    '<input type="hidden" name="token" value="' + req.params.token + '" />' +
    '<input type="password" name="password" value="" placeholder="Enter your new password..." />' +
    '<input type="submit" value="Reset Password" />' +
  '</form>'+'/footer-end');
  });
});

router.post('/resetpassword', function(req, res) {
  // TODO: Fetch user from database using
  // req.body.id
  var db = require('../db.js');
  db.query('SELECT * FROM users WHERE id = ?',[req.body.id],(err,results,fields)=>{
    if(err){
      console.log('Error in reseting the password of the' + req.body.id);
    }
    //console.log(results[0].id);
    else{
    var date = new Date(results[0].regdate);
    var secret = results[0].password + '-' + date.getTime();
    }
    //console.log(secret);
    //console.log(Token);
    var payload = jwt.decode(req.params.token, secret);
    res.send('Your password has been successfully changed.');
  });
  // TODO: Decrypt one-time-use token using the user's
  // current password hash from the database and combining it
  // with the user's created date to make a very unique secret key!
  // For example,
  // var secret = user.password + ‘-' + user.created.getTime();
  //var secret = 'fe1a1915a379f3be5394b64d14794932-1506868106675';

  //var payload = jwt.decode(req.body.token, secret);

  // TODO: Gracefully handle decoding issues.
  // TODO: Hash password from
  // req.body.password
  
});

                                                          
router.get('/register', function (req, res, next) {
  res.render('register', {
    title: 'Registration'
  });
});

router.post('/register', function (req, res, next) {
  //using express validator to validate the data 
  req.checkBody('username', 'Username field cannot be empty.').notEmpty();
  req.checkBody('username', 'Username must be between 4-15 characters long.').len(4, 15);
  req.checkBody('email', 'The email you entered is invalid, please try again.').isEmail();
  req.checkBody('email', 'Email address must be between 4-100 characters long, please try again.').len(4, 100);
  req.checkBody('password', 'Password must be between 8-100 characters long.').len(8, 100);
  req.checkBody("password", "Password must include one lowercase character, one uppercase character, a number, and a special character.").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i");
  req.checkBody('passwordMatch', 'Password must be between 8-100 characters long.').len(8, 100);
  req.checkBody('passwordMatch', 'Passwords do not match, please try again.').equals(req.body.password);
  const errors = req.validationErrors();
  if (errors) {
   // console.log(`errors:${JSON.stringify(errors)}`);
    res.render('register', {
      title: 'Registration Error',
      errors: errors
    });
  } else {
    //storing the data comming form post resquest 
 
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    const db = require('../db.js');

    bcrypt.hash(password, saltRounds, function (err, hash) {
      // Store hash in your password DB.
      let sql = "INSERT INTO users(username,email,password,regdate) VALUES (?,?,?,NOW())";
      db.query(sql, [username, email, hash], (error, result, fields) => {
        if (error) throw error;

        db.query('SELECT LAST_INSERT_ID() as user_id', (error, result, field) => {
          if (error) throw error;

          const user_id = result[0];
         // console.log(result[0]);
          req.login(user_id, (err) => {
            res.redirect("/");
          });
        });

      });
    });
  }
});

passport.serializeUser(function (user_id, done) {
  done(null, user_id);
});

passport.deserializeUser(function (user_id, done) {
  done(null, user_id);
});

function authenticationMiddleware() {
  return (req, res, next) => {
    console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);
    console.log(`My user id is :  ${JSON.stringify(req.user)}`);

    if (req.isAuthenticated()) return next();
    res.redirect('/login');
  }
}
module.exports = router;