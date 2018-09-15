// Require all we need 
var passport = require('passport'), 
    FacebookStrategy = require('passport-facebook').Strategy,
    GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
    mysql = require('mysql'),
    credentials = require('../credentials');

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
                    // we only get here on successful authentication

                    res.redirect(303, options.successRedirect);
                },
            );

            app.get('/auth/google', passport.authenticate('google', { scope: ['email'] }));

            app.get('/auth/google/callback',
                passport.authenticate('google', {failureRedirect: options.failureRedirect}),
                function(req, res){
                    res.redirect(303, options.successRedirect);
                }
            );
            
        },
    };
};