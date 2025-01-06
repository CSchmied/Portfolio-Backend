// server.js
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2")
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');

const app = express();

app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many login attempts from this IP, please try again later.',
});

const connection = mysql.createConnection({
	host     : 'localhost',
	user     : 'root',
	password : '',
	database : 'nodelogin'
});

app.post('/signup', (req, res) => {
  const name = req.body.name
  const password = req.body.password;
  const email = req.body.email;

  connection.query("INSERT INTO accounts (name, password, email) VALUES (?, ?, ?)", [name,password,email], (err, data) => {
    if (err) {
       return res.json(err);
    }
    return res.json(data);
  })
})

app.post('/login', loginLimiter, (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  connection.query('SELECT * FROM accounts WHERE email = ? AND password = ?', [email, password], (err, data) => {
    if (err) {
      console.error(err); // Log the error for debugging
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (data.length > 0) {
      const user = data[0];
      console.log(user)
      const strPassword = password.toString();
      const storedHashedPassword = user.password;
      // Check to make sure the hashed password matches the one we're given
      // console.log('Password:', strPassword, 'Type:', typeof strPassword);
      // console.log('Stored Hashed Password:', storedHashedPassword, 'Type:', typeof storedHashedPassword);
      const match = bcrypt.compare(strPassword, storedHashedPassword);
      if (match) {
        // Store user information in the session
        req.session.userId = user.id; // Store user ID or any other info
        req.session.name = user.name; // Store user name or any other info
        req.session.email = user.email; // Store email or other info
        return res.json({ message: 'Success', user: { id: user.id, name: user.name, email: user.email } });
      }    }
    else {
      return res.json('Failed');
    }
  })
  })

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Could not destroy session');
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

app.listen(8081, () => {
  console.log(`Server is running on port 8081.`);
});