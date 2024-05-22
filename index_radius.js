const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const jwtSecret = require('crypto').randomBytes(16); // 16*8=256 random bits 
const cookieParser = require('cookie-parser');
const JwtStrategy = require('passport-jwt').Strategy;
const fs = require('fs');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const scryptMcf = require('scrypt-mcf');
const { log } = require('console');
const session = require('express-session'); 
const dotenv = require('dotenv');
const axios = require('axios');
const { Issuer, Strategy: OpenIDConnectStrategy } = require('openid-client');

const Client = require('node-radius-client');

dotenv.config({ path: './pass.env' });

const privateKey = fs.readFileSync('server.key', 'utf8');
const certificate = fs.readFileSync('server.cert', 'utf8');
const credentials = { key: privateKey, cert: certificate };

const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');

const radius = new Client({
  host: '127.0.0.1',
  dictionaries: [
    file,
  ],
});

async function initializeOIDCClient() {
  try {
    const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER);
    //console.log('Discovered issuer %s %O', oidcIssuer.issuer, oidcIssuer.metadata);

    const oidcClient = new oidcIssuer.Client({
      client_id: process.env.OIDC_CLIENT_ID,
      client_secret: process.env.OIDC_CLIENT_SECRET,
      redirect_uris: [process.env.OIDC_CALLBACK_URL],
      response_types: ['code']
    });

    console.log(oidcClient)

    return oidcClient;
  } catch (error) {
    console.error('Error discovering OIDC issuer:', error);
    throw error;
  }
}

(async () => {
  try {
    const oidcClient = await initializeOIDCClient();
    const app = express();
    const port = 3000;

    const db = new sqlite3.Database('./mydb.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
      if (err) {
        console.error(err.message);
      } else {
        console.log('Connected to the mydb.db SQLite database.');
        initializeDatabase();
        registerUser('walrusfast', 'walrus', 8);
        registerUser('walrusslow', 'walrus', 20);
        registerUser("alanis", 'alanis', 8);
      }
    });

    function initializeDatabase() {
      db.serialize(() => {
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, hash TEXT, salt TEXT)", (err) => {
          if (err) {
            console.error('Error creating table:', err.message);
          } else {
            console.log('Table users is ready.');
          }
        });
      });
    }

    async function registerUser(username, password, N) {
      const derivedKeyLength = 64;
      const scryptParams = {
        logN: N,
        r: 8,
        p: 2
      };
      const key = await scryptMcf.hash(password, { derivedKeyLength: derivedKeyLength, scryptParams: scryptParams });
      db.run("INSERT OR REPLACE INTO users (username, hash) VALUES (?,?)", [username, key]);
    }

    app.use(logger('dev'));
    app.use(session({
      secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
      resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
      saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
    }));
    app.use(cookieParser());

    // We will store in the session the complete passport user object
    passport.serializeUser(function (user, done) {
      return done(null, user);
    });

    // The returned passport user is just the user object that is stored in the session
    passport.deserializeUser(function (user, done) {
      return done(null, user);
    });

    passport.use('examiners', new JwtStrategy(
      {
        jwtFromRequest: (req) => {
          if (req && req.cookies) { return req.cookies.jwt; }
          return null;
        },
        secretOrKey: jwtSecret
      },
      function (jwtPayload, done) {
        if (jwtPayload.sub) {
          const user = {
            username: jwtPayload.sub,
            description: 'one of the users that deserve to get to this server',
            role: jwtPayload.role ?? 'user',
          };
          if (jwtPayload.examiner == true) {
            return done(null, user);
          }
        }
        return done(null, false);
      }
    ));

    passport.use('local-radius', new LocalStrategy(
	  {
	    usernameField: 'username',
	    passwordField: 'password',
	    session: false
	  },
	  async function(username, password, done) {
	    try {
	      const response = await radius.accessRequest({
		secret: 'testing123',
		attributes: [
		  [attributes.USER_NAME, username],
		  [attributes.USER_PASSWORD, password],
		],
	      }).then((result) => {
		console.log('result', result);
		if (result.code === 'Access-Accept') {
		  return done(null, { username });
		} else {
		  return done(null, false);
		}
	      });
	    } catch (error) {
	      console.log('resulterror', error.response, username);
	      return done(null, false);
	    }
	  }
	));

    passport.use('jwtCookie', new JwtStrategy(
      {
        jwtFromRequest: (req) => {
          if (req && req.cookies) { return req.cookies.jwt; }
          return null;
        },
        secretOrKey: jwtSecret
      },
      function (jwtPayload, done) {
        if (jwtPayload.sub) {
          const user = {
            username: jwtPayload.sub,
            description: 'one of the users that deserve to get to this server',
            role: jwtPayload.role ?? 'user',
          };
          return done(null, user);
        }
        return done(null, false);
      }
    ));

    passport.use('username-password', new LocalStrategy(
      {
        usernameField: 'username',
        passwordField: 'password',
        session: false
      },
      function (username, password, done) {
        db.get("SELECT hash FROM users WHERE username = ?", [username], (err, row) => {
          if (err) return done(err);
          if (!row) return done(null, false);

          scryptMcf.verify(password, row.hash).then(result => {
            if (result) {
              return done(null, { username: username });
            } else {
              return done(null, false);
            }
          });
        });
      }
    ));

    passport.use('oidc', new OpenIDConnectStrategy({
      client: oidcClient,
      usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
    }, (tokenSet, userInfo, done) => {
      console.log(tokenSet, userInfo);
      if (tokenSet === undefined || userInfo === undefined) {
        return done('no tokenSet or userInfo');
      }
      return done(null, userInfo);
    }));

    app.use(express.urlencoded({ extended: true }));
    app.use(passport.initialize());

    app.get('/',
      passport.authenticate(
        'jwtCookie',
        { session: false, failureRedirect: '/login' }
      ),
      (req, res) => {
        res.send(`Welcome to your private page, ${req.user.username}!`);
      }
    );

    app.get('/oidc/login',
      passport.authenticate('oidc', { scope: 'openid email' })
    );

    app.get('/oidc/cb', passport.authenticate('oidc', {
      failureRedirect: '/login', failureMessage: true
    }), (req, res) => {
      jwtClaims = {
        sub: req.user.email,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user', // just to show a private JWT field
        examiner: true
      };

      const token = jwt.sign(jwtClaims, jwtSecret);
      res.cookie('jwt', token, { httpOnly: true, secure: true });
      res.redirect('/');
    });

    app.get('/oauth2cb', async (req, res, next) => {
      try {
        console.log(process.env.OAUTH2_TOKEN_URL);
        const code = req.query.code;

        if (!code) {
          throw new Error('No code provided');
        }

        const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
          client_id: process.env.OAUTH2_CLIENT_ID,
          client_secret: process.env.OAUTH2_CLIENT_SECRET,
          code
        }, {
          headers: {
            'Accept': 'application/json'
          }
        });

        const accessToken = tokenResponse.data.access_token;
        const scope = tokenResponse.data.scope;

        if (!accessToken) {
          throw new Error('No access token received');
        }

        if (scope !== 'user:email') {
          throw new Error('User did not consent to release email');
        }

        const userDataResponse = await axios.get(process.env.USER_API, {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        });

        console.log(userDataResponse.data);

        const jwtClaims = {
          sub: userDataResponse.data.email, // Assuming the email is in userDataResponse.data.email
          iss: 'localhost:3000',
          aud: 'localhost:3000',
          exp: Math.floor(Date.now() / 1000) + 604800,
          role: 'user',
          examiner: true
        };

        const token = jwt.sign(jwtClaims, jwtSecret);
        res.cookie('jwt', token, { httpOnly: true, secure: true });
        res.redirect('/');
      } catch (err) {
        console.error(err);
        res.status(err.status || 500).send(err.message);
      }
    });

    app.get('/onlyexaminers',
      passport.authenticate(
        'examiners',
        { session: false, failureRedirect: '/' }
      ),
      (req, res) => {
        res.send('hello examiner');
      }
    );

    app.get('/logout', (req, res) => {
      res.cookie('jwt', '', { expires: new Date(0) });
      res.redirect('/login');
    });

    app.get('/login',
      (req, res) => {
        res.sendFile('login.html', { root: __dirname });
      }
    );

    app.post('/login',
      passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
      (req, res) => {
        // This is what ends up in our JWT
        console.error(req.user.username);
        if (req.user.username != "alanis") {
          jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:3000',
            aud: 'localhost:3000',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user', // just to show a private JWT field
            examiner: false
          };
        }
        if (req.user.username == "alanis") {
          console.error(req.user.username);
          jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:3000',
            aud: 'localhost:3000',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user', // just to show a private JWT field
            examiner: true
          };
        }

        // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
        const token = jwt.sign(jwtClaims, jwtSecret);
        res.username = req.user.username;
        res.cookie('jwt', token, { httpOnly: true, secure: true }); // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
        res.redirect('/');

        // And let us log a link to the jwt.io debugger for easy checking/verifying:
        //console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        //console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
      }
    );

	app.post('/radius/login',
	  passport.authenticate('local-radius', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'local-radius' passport strategy, which we defined before
	  (req, res) => {
            const jwtClaims = {
              sub: req.user.username,
              iss: 'localhost:3000',
              aud: 'localhost:3000',
              exp: Math.floor(Date.now() / 1000) + 604800,
              role: 'user',
              examiner: true
            };

            const token = jwt.sign(jwtClaims, jwtSecret);
            res.cookie('jwt', token, { httpOnly: true, secure: true });
            res.redirect('/');
	  }
	);


    app.use(function (err, req, res, next) {
      console.error(err.stack);
      res.status(500).send('Something broke!');
    });

    const httpsServer = https.createServer(credentials, app);

    httpsServer.listen(port, () => {
      console.log(`Example app listening at https://localhost:${port}`);
    });
  } catch (error) {
    console.error('Error starting server:', error);
  }
})();

