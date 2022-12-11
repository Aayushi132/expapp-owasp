const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user"),
      mongoSanitize         =  require('express-mongo-sanitize'),
      rateLimit             =  require('express-rate-limit'),
      xss                   =  require('xss-clean'),
      helmet                =  require('helmet'),
    { check, validationResult }= require('express-validator');



//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:true,
    cookie:{
        httpOnly:true,
        secure:true,
        maxAge:1*60*1000
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================
app.use(mongoSanitize());
const limit=rateLimit({
    max: 100,
    windowMS: 60* 60* 1000,
    message: 'Too many requests'
})
app.use('/routeName',limit)
app.use(express.json({limit:'10kb'}));
app.use(xss());
app.use(helmet());
//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register");
});


app.post("/register",  [
    check('username')
    .isLength({ min: 1})
    .withMessage('Please enter a Username')
    .isLength({ max: 6})
    .withMessage('Cannot be greater than 6'),
    check('password')
    .isLength({ min: 1 , max:8})
    .withMessage('Please enter a password at least 8 character .')
    .matches(/\d/)
    .withMessage('Password must contain a number')
    .matches(  /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z\d@$.!%*#?&]/,),
],(req,res)=>{
  
    const errors = validationResult(req);
    if(errors.isEmpty()) {
        
    User.register(new User({username: req.body.username,email: req.body.email,phone: req.body.phone}),req.body.password,function(err,user){
        if(err){
            console.log(err);
            return res.render('register');
        }
        passport.authenticate("local")(req,res,function(){
            res.redirect("/login");
        })    
    });
}  else {
    res.render('register', { 
        title: 'Registration form',
        errors: errors.array(),
        data: req.body,
     });
  }
})







app.get("/logout",(req,res)=>{
    req.logout ,()=>{};
    res.redirect("/");
});

function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});