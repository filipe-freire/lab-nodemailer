const { Router } = require('express');
const router = new Router();

const routeGuard = require('./../middleware/route-guard');

const User = require('./../models/user');
const bcryptjs = require('bcryptjs');
const dotenv = require('dotenv');
dotenv.config();
const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  }
});

const generateRandomToken = length => {
  const characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += characters[Math.floor(Math.random() * characters.length)];
  }
  return token;
};

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const { name, email, password } = req.body;
  const confirmationToken = generateRandomToken(10);
  const confirmationUrl = `http://localhost:3000/authentication/confirm-email?token=${confirmationToken}`;
  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        confirmationToken: confirmationToken
      });
    })
    .then(user => {
      req.session.user = user._id;

      transport
        .sendMail({
          from: process.env.NODEMAILER_EMAIL,
          to: user.email,
          subject: 'Click the link to activate your account!',
          html: `<html>
                    <head>
                      <style>
                        a {
                        background-color: skyblue;
                        </style>
                    </head>
                    <body>
                    <a href="${confirmationUrl}"> Link to confirm email </a>
                    </body>
                  </html>
                `
        })
        .then(result => {
          console.log('Email was sent ', result);
        })
        .catch(error => {
          console.log('There was an error sending the email', error);
        });

      res.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

router.get('/authentication/confirm-email', (req, res, next) => {
  console.log('hey there!');
  const token = req.query.token;
  console.log(token);
  User.findOneAndUpdate({ confirmationToken: token }, { status: 'active' }, { new: true })
    .then(user => {
      console.log(user);
      res.render('confirmation', { user }); //render confirmation page
    })
    .catch(error => console.log(error));
});

// PROFILE PAGE

router.get('/profile', routeGuard, (req, res, next) => {
  // User.findById(userId);
  res.render('profile');
  // console.log(req.user);
});

// SIGN IN

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

module.exports = router;
