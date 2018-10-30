var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var passport = require('passport');
const bcrypt = require('bcrypt');
const saltRounds = 10;


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
  const db = require('../db.js');
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


router.get('/login', (req,res)=>{
  res.render('login',{title:'login'});
});

router.post('/login', passport.authenticate('local', {
  successRedirect:'/profile/',
  failureRedirect:'/login/'
}));

router.get('/logout', (req,res)=>{
  req.logout();
  req.session.destroy();
  res.redirect('/');
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
      let sql = "INSERT INTO users(username,email,password) VALUES (?,?,?)";
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