// Require all we need 
var AmazonCognitoIdentity = require('amazon-cognito-identity-js');
    passport = require('passport'), 
    FacebookStrategy = require('passport-facebook').Strategy,
    GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
    CognitoStrategy = require('passport-cognito'),
    mysql = require('mysql'),
    credentials = require('../credentials'),
    dialog = require('dialog');


var CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;

var poolData = {
    UserPoolId : credentials.authProviders.cognito.userPoolId, // Your user pool id here
    ClientId : credentials.authProviders.cognito.clientId // Your client id here
};

var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

// Set up connection to database

var userTable = "ico_users",
    connection = mysql.createConnection({
        host     : credentials.dbProviders.host,
        user     : credentials.dbProviders.user,
        password : credentials.dbProviders.pwd,
        database : credentials.dbProviders.db,
    });

// Mapping user between client <-> server <-> database
// Particulary, userid in session <-> user instance in database
passport.serializeUser(function(user, done){ 
    // Map user instance to id
    done(null,user.id);
});

passport.deserializeUser(function(id, done){ 
    // Map id to user instance in database
    var query = "SELECT * FROM " + userTable + " WHERE `id`=?";
    connection.query(query, [id],  function(err,rows) {	
        // Error if query failed or no user found in database
        if(err || rows.length<=0)
            done(err, null);
        // Otherwuse, give user instance to Passport
        done(null, rows[0]);
    });
});


// Export auth module with 2 functionality : init and register routes
module.exports = function(app, options){

    // if success and failure redirects aren't specified,
    // set some reasonable defaults 
    if(!options.successRedirect) options.successRedirect = '/';
    if(!options.failureRedirect) options.failureRedirect = '/login';
    
    return {
        
        // Function that is used to configure strategy for Passport
        init: function() {
            // Configure Facebook strategy
            passport.use(new FacebookStrategy({ 
                    clientID: credentials.authProviders.facebook.appId, 
                    clientSecret: credentials.authProviders.facebook.appSecret, 
                    callbackURL: '/auth/facebook/callback',
                    profileFields: ['id', 'displayName', 'email'],
                }, function(accessToken, refreshToken, profile, done){
                    // We will get to this function if user finish FB authentication
                    var authId = profile.id;
                    var authParty = 'facebook';
                    var now = new Date();
                    
                    // Find or create user in database
                    var query = "SELECT * FROM " + userTable +  " WHERE authId=? AND authParty=?";
                    connection.query(query, [authId, authParty],function(err,rows) {

                        if(err || rows === undefined) {
                            return done(err, null);
                        }
                        
                        // User exists
                        if(rows.length > 0) {
                            return done(null, rows[0]);
                        }
                        // User not exist, create user
                        else {
                            var insertQuery = "INSERT INTO " + userTable + " (`name`, `email`, `createTime`, `authId`, `authParty`, `role`) values (?, ?, ?, ?, ?, 'customer')";
                            console.log(insertQuery);
                            connection.query(insertQuery, [profile._json.name, profile._json.email, now, profile.id, authParty], function(err,result){
                                if(err) {
                                    return done(err, null);
                                }

                                connection.query(query, [authId, authParty],function(err,rows) {
                                    // Error if query failed or no user found in database
                                    if(err || rows === undefined || rows.length<=0)
                                        done(err, null);
                                    // Otherwuse, give user instance to Passport
                                    done(null, rows[0]);
                                });
                                
                            });	
                        }
                    });

                    console.log("We get user profile ");
                    console.log(profile);
            }));
                    // 
                    
            passport.use(new GoogleStrategy({
                    clientID: credentials.authProviders.google.appId,
                    clientSecret: credentials.authProviders.google.appSecret,
                    callbackURL: "/auth/google/callback"
                }, function(token, tokenSecret, profile, done){
                    var authId = profile.id;
                    var authParty = 'google';
                    var now = new Date();

                    var query = "SELECT * FROM " + userTable +  " WHERE authId=? AND authParty=?";
                    connection.query(query, [authId, authParty],function(err,rows) {

                        if(err || rows === undefined) {
                            return done(err, null);
                        }
                        
                        // User exists
                        if(rows.length > 0) {
                            return done(null, rows[0]);
                        }
                        // User not exist, create user
                        
                        else {
                            var insertQuery = "INSERT INTO " + userTable + " (`name`, `email`, `createTime`, `authId`, `authParty`, `role`) values (?, ?, ?, ?, ?, 'customer')";
                            console.log(insertQuery);
                            connection.query(insertQuery, [profile._json.displayName, profile._json.emails[0].value, now, profile.id, authParty], function(err,result){
                                if(err) {
                                    return done(err, null);
                                }

                                connection.query(query, [authId, authParty],function(err,rows) {
                                    // Error if query failed or no user found in database
                                    if(err || rows === undefined || rows.length<=0)
                                        done(err, null);
                                    // Otherwuse, give user instance to Passport
                                    done(null, rows[0]);
                                });
                                
                            }); 
                        }
                    });

                    console.log("We get user profile ");
                    console.log(profile);
            }));
                   
                    // if err , done(err, null)
            
            passport.use(new CognitoStrategy({
                userPoolId: credentials.authProviders.cognito.userPoolId,
                clientId: credentials.authProviders.cognito.clientId,
                region: credentials.authProviders.cognito.region
                }, function(accessToken, idToken, refreshToken, profile, done) {
                    //self._verify(accessToken, idToken, refreshToken, profile, verified);
                    var authId = profile.sub;
                    var authParty = 'cognito';
                    var now = new Date();
                    
                    var query = "SELECT * FROM " + userTable +  " WHERE authId=? AND authParty=?";
                    connection.query(query, [authId, authParty],function(err,rows) {

                        if(err || rows === undefined) {
                            return done(err, null);
                        }
                        
                        // User exists
                        if(rows.length > 0) {
                            return done(null, rows[0]);
                        }
                        // User not exist, create user
                        
                        else {
                            var insertQuery = "INSERT INTO " + userTable + " (`name`, `email`, `createTime`, `authId`, `authParty`, `role`) values (?, ?, ?, ?, ?, 'customer')";
                            console.log(insertQuery);
                            connection.query(insertQuery, [profile.name, profile.email, now, profile.sub, authParty], function(err,result){
                                if(err) {
                                    return done(err, null);
                                }

                                connection.query(query, [authId, authParty],function(err,rows) {
                                    // Error if query failed or no user found in database
                                    if(err || rows === undefined || rows.length<=0)
                                        done(err, null);
                                    // Otherwuse, give user instance to Passport
                                    done(null, rows[0]);
                                });
                                
                            }); 
                        }
                    });

                    console.log("We get user profile ");
                    console.log(profile);
                   }
            )); 

            // Initialize Passport and restore authentication state, if any, from the session.
            app.use(passport.initialize());
            app.use(passport.session());
        }, 
        
        // Function that is used to register auth routes to express
        registerRoutes: function() {
            // Register Facebook auth routes
            app.get('/auth/facebook',  passport.authenticate('facebook',  { scope: ['email'] })); // extend permission to ask for email

            // Register Facebook callback route
            app.get('/auth/facebook/callback', 
                passport.authenticate('facebook', {failureRedirect: options.failureRedirect }), 
                function(req, res){
                    res.redirect(303, options.successRedirect);
                }
            );

            app.get('/auth/google', passport.authenticate('google', { scope: ['email'] }));

            app.get('/auth/google/callback',
                passport.authenticate('google', {failureRedirect: options.failureRedirect}),
                function(req, res){
                    res.redirect(303, options.successRedirect);
                }
            );

            app.post('/auth/cognito', 
              passport.authenticate('cognito', {
                    successRedirect: options.successRedirect,
                    failureRedirect: options.failureRedirect,
                    failureFlash: true
                })
            );


            app.post('/process/signup', function(req, res){
                if(req.body.password !== req.body.repeatPassword){
                    dialog.info('Password doesn\'t match!');
                    res.redirect('back');
                }else{
                    var attributeList = [];
                    var dataEmail = {
                        Name : 'email',
                        Value : req.body.email
                    };

                    var dataName = {
                        Name : 'name',
                        Value : req.body.name
                    }
                    var attributeEmail = new AmazonCognitoIdentity.CognitoUserAttribute(dataEmail);
                    var attributeName = new AmazonCognitoIdentity.CognitoUserAttribute(dataName);

                    attributeList.push(attributeEmail);
                    attributeList.push(attributeName);


                    userPool.signUp(req.body.email, req.body.password, attributeList, null, function(err, result){
                        if (err) {
                            dialog.info(err.message || JSON.stringify(err));
                            console.log(err.message || JSON.stringify(err));
                            return;
                        }
                        cognitoUser = result.user;
                        console.log('user name is ' + cognitoUser.getUsername());
                        dialog.info('Sign up successfully! Please check your email and click the verification link!');
                    });

                    res.redirect(303, '/signup')
                }
                
            });

                
            
            
        },
    };
};