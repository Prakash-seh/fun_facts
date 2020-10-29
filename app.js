require("dotenv").config();
const parse = require("csv-parse");
const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const flash = require("connect-flash");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const csvData = [];
fs.createReadStream(__dirname + "/facts.csv")
    .pipe(
        parse({
            delimiter: ","
        })
    )
    .on("data", function(dataRow) {
        csvData.push(dataRow);
    })
    .on("end", function() {
        console.log("csv successfull");
    })

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended : true}));
app.use(flash());

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost/facts_user", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    username: String,
    googleId: String,
    facebookId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id, username: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id, username: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.use(function(req, res, next){
    res.locals.currentUser = req.user;
    res.locals.error = req.flash("error");
    res.locals.success = req.flash("success");
    next();
})

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), function(req, res) {
    // Successful authentication, redirect secret.
    req.flash("success", "Successfully logged In as " + req.user.username);
    res.redirect('/fact');
});

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/secrets", passport.authenticate("facebook", {failureRedirect : "/login"}), function(req, res) {
    // Successful authentication, redirect secret. 
    req.flash("success", "Successfully logged In as " + req.user.username);   
    res.redirect("/fact");
})

app.get("/", (req, res) => {
    res.redirect("/home");
})

app.get("/home", (req, res) => {
    res.render("home");
});

app.get("/login", (req, res) => {
    res.render("login");
})

// =================================================================================================
// On incorrect login credentials => show Password or username is incorrect rather than unauthorized
// =================================================================================================

app.post("/login", passport.authenticate("local", { failureRedirect: "/login", failureFlash: true }), function(req, res) {
    req.flash("success", "Successfully logged In as " + req.user.username);
    res.redirect('/fact');
});

// ==============================================================================================
// On incorrect login credentials => show unauthorized rather than showing invalid credentials
// ==============================================================================================

// app.post("/login", (req, res) => {
//     const newUser = new User({
//         username: req.body.username,
//         password: req.body.password
//     });
//     req.login(newUser, function(err) {
//         if (err) {
//             console.log(err);
//             res.redirect("/login");
//         } else {
//             passport.authenticate("local")(req, res, function() {
//                 req.flash("success", "Successfully logged In as " + req.user.username);  
//                 res.redirect("/fact");
//             });
//         }
//     });
// })

app.get("/register", (req, res) => {
    res.render("register")
})

app.post("/register", (req, res) => {
    User.register({email : req.body.email, username: req.body.username}, req.body.password, (err, registered_user) => {
        if (err) {
            req.flash("error", err.message);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                req.flash("success", "Successfully registered as " + req.user.username);  
                res.redirect("/fact");
            });
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout();
    req.flash("success", "Successfully logged out");
    res.redirect("/home");
});

app.get("/fact",(req, res) => {
    if(req.isAuthenticated()) {
        res.render("fact.ejs", {fact: csvData[Math.floor(Math.random() * 101)]});
    } else {
        req.flash("error", "You need to login first")
        res.redirect("/login");
    }
});

app.get("*", (req, res) => {
    res.render("error");
})

app.listen('3000', () => {
    console.log("Port 3000, Listening....");
});