var express = require('express');
var bodyParser = require('body-parser')
var User = require('./models').User
var cors = require('cors')
var validator = require('express-validator')

var app = express()

app.use(express.static('public'))
app.use(bodyParser.json())
app.use(cors())
app.use(validator())

const authorization = function(req, res, next) {
  const token = req.query.authToken || req.body.authToken
  if (token) {
    User.findOne({
      where: {
        authToken: token
      }
    }).then((user) => {
      if (user) {
        req.currentUser = user
        next()
      } else {
        res.status(401)
        res.json({
          message: 'Authorization Token Invalid'
        })
      }
    })
  } else {
    res.status(401)
    res.json({
      message: 'Authorization Token Required'
    })
  }
}

app.get('/users',
  authorization,
  function(req, res) {
    res.json({
      user: req.currentUser
    })
  })

app.post('/users', (req, res) => {
  req.checkBody('firstName', 'is required').notEmpty()
  req.checkBody('lastName', 'is required').notEmpty()
  req.checkBody('email', 'is required').notEmpty()
  req.checkBody('password', 'is required').notEmpty()

  req.getValidationResult()
    .then((validationErrors) => {
      if (validationErrors.isEmpty()) {
        const {
          firstName,
          lastName,
          email,
          password
        } = req.body

        User.create({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: password
          })
          .then((user) => {
            res.status(201)
            res.json({
              user: user
            })
          })
          .catch(e => {
            res.status(400)
            res.json({
              errors: [`error creating user: ` + e]
            })
          })
      } else {
        res.status(400)
        res.json({
          errors: {
            validations: validationErrors.array()
          }
        })
      }
    })
    .catch(e => {
      res.status(400)
      res.json({
        errors: [`error validating create user: ` + e]
      })
    })
})

app.post('/login', (req, res) => {
  req.checkBody('email', 'Is required').notEmpty()
  req.checkBody('password', 'Is required').notEmpty()

  const {
    email,
    password
  } = req.body

  req.getValidationResult()
    .then((validationErrors) => {
      if (validationErrors.isEmpty()) {
        User.findOne({
            where: {
              email: email
            }
          })
          .then((user) => {
            if (user && user.verifyPassword(password)) {
              // the password is valid -- now we need to set the auth token...
              user.setAuthToken()

              res.json({
                authToken: user.authToken,
              })
            } else {
              res.status(401)
              res.json({
                errors: [
                  "invalid username/password combination"
                ]
              })
            }
          })
      } else {

        res.status(400)

        res.json({
          errors: {
            validations: validationErrors.array()
          }
        })

      }
    })
})

module.exports = app
