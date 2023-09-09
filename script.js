//Authentication using session
const express = require('express');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const multer = require('multer');
const session = require('express-session')
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const axios = require('axios');
const app = express();
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public");
  },
  filename: (req, file, cb) => {
    console.log(file);
    cb(null, file.originalname);
  },
});
const upload = multer({ storage: storage });
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
let Users = require('./DB.json');
const store = new session.MemoryStore();
app.use(
  session({
    secret: 'mySecretKey', 
    resave: false, 
    saveUninitialized: true,
    cookie: {
      maxAge: 60*60*1000*24,
      secure: false,
      httpOnly: true
    },
    store,
  })
);
app.get('/login',CheckAuthentication,(req, res) => {
  return  res.render('login')
})
app.post('/login', [
    body("username").notEmpty().trim().escape()
], (req, res) => {
  const { username, password } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send("you didn't fill the username field correctly");
  }
  const DataSecure = {
    username: xss(username),
    password : xss(password)
  }
  const user = Users.users.find(user => user.username === DataSecure.username);
  if (!user) {
    return res.status(400).send("you are not registered");
  }
  bcrypt.compare(DataSecure.password, user.password).then(valid => {
    if (!valid) {
      return res.send("your password is incorrect");
    } 
    req.session.authenticated = true;
    const image = user.image
    req.session.user = {username,image};
    console.log(req.session);
    res.redirect('/dashboard');
  
  })
  
})
app.get('/register',CheckAuthentication,(req, res) => {
   return res.render('register')
})
app.post('/register', upload.single("image"), [
    body("username").notEmpty().trim().escape(),
    body("password").isLength({ min: 4 }),
    body("ConfirmPassword").isLength({ min: 4 })
], async (req, res) => {
    const { username, password, ConfirmPassword } = req.body;
    if (password !== ConfirmPassword) {
        return res.send("your password and confirmPassword are not the same")
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send("Your password is Weak or username is wrong")
    }
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    const DataSecure = {
        username: xss(username),
        password: xss(hashedPassword),
        image: xss(req.file.filename)
    }
   // console.log(DataSecure);
    axios.post("http://localhost:3000/users", DataSecure);   
    return res.redirect("login");
});
app.get('/dashboard', ensureAuthentication,(req, res) => {
  
   return res.render('dashboard',{user:req.session.user})
})
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
     console.log("Error destroying session : ",err )
    }
    res.redirect('/login');
 })
})

app.listen('8000', (req, res) => {
    console.log('listening at port 8000');
})
//middlewares for authentication
function ensureAuthentication(req, res, next) {
  if (req.session.authenticated) {
    return next();
  } else {
    res.redirect('/login');
  }
}
function CheckAuthentication(req, res, next) {
  if (req.session.authenticated) {
    return res.redirect('/dashboard');
  }
  next()
}