// Load the things we need
var express = require('express');
var exphbs  = require('express-handlebars');
var bodyParser = require('body-parser');
var credentials = require('./credentials');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var uuid = require('uuid/v4');
var flash = require('connect-flash');





/////////////////////////////
// Only for test
var fs = require('fs');
var https = require('https');
var privateKey  = fs.readFileSync('./ssl/ico.pem', 'utf8');
var certificate = fs.readFileSync('./ssl/ico.crt', 'utf8');
var ssl = { key: privateKey, cert: certificate };
/////////////////////////////



var app = express();

// Set middleware 
app.use(cookieParser());   
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(flash());

// Static content 
app.use("/userpanel", express.static(__dirname + "/public/userpanel")); // for any url that start wih /userpanel (user panel page)
app.use(express.static(__dirname + '/public/main')); // for other page(main page)


app.use(session({
    genid: (req) => {
      console.log('Inside the session middleware');
      return uuid(); // use UUIDs for session IDs
    },
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
  }))



// Set the view engine
app.engine('handlebars', exphbs({defaultLayout: 'main'}));
app.set('view engine', 'handlebars');

//app.enable('view cache');



// Set authentication 
var auth = require('./lib/auth.js')(app, {
    successRedirect: '/', 
    failureRedirect: '/login',
});

// Links in Passport middleware
auth.init();

// Set authentication routes
auth.registerRoutes();


// Set render page routes
// index page 
app.get('/', function(req, res) {
    res.render('index',  {layout: false} ); // not using layout
});
// login page
app.get('/login', function(req, res) {
    res.render('login-light',  {layout: false} ); // not using layout
});
// signup page
app.get('/signup', function(req, res) {
    res.render('signup-light',  {layout: false} ); // not using layout
});


// dashboard page
app.get('/userpanel/dashboard', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('dashboard', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// kyc page
app.get('/userpanel/kyc', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('kyc', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// kyc-application page
app.get('/userpanel/kyc-application', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('kyc-application', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// tokens page
app.get('/userpanel/tokens', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('tokens', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// transactions page
app.get('/userpanel/transactions', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('transactions', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// referrals page
app.get('/userpanel/referrals', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('referrals', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// account page
app.get('/userpanel/account', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('account', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// security page
app.get('/userpanel/security', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('security', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// activity page
app.get('/userpanel/activity', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('activity', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// howto page
app.get('/userpanel/howto', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('howto', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// faq page
app.get('/userpanel/faq', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('faq', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});
// policy page
app.get('/userpanel/policy', function(req, res) {
    if(req.isAuthenticated()) {
        console.log(req.cookies);
        res.render('policy', {layout: 'userpanel'} ); // not using layout
    }
    else{
        console.log("not authorized");
        console.log(req.cookies);
        res.redirect(303, "/login");
    }

    
});


// Logout
app.get('/logout', function(req, res) {
    
    // Using only req.logout is not sufficient
    req.session.destroy((err) => {
        if(err) return next(err);
    
        req.logout();
    
        res.redirect(303, '/');
    });

});


// Set form handling routes
app.post('/signup', function(req, res) {
    console.log("receive shit");

    // Return to home page
    res.redirect(303, '/')
});




// app.listen(8080);
// console.log('8080 is the magic port');


/////////////////////////////
// Only for test
https.createServer(ssl, app).listen(8080);
console.log('Using https at 8080 port for development use...');
/////////////////////////////