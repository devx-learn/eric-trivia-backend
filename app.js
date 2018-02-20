var express = require('express');
var cors = require('cors')
var bodyParser = require('body-parser')
var validator = require('express-validator')
var app = express();
var Person = require('./models').Person
var logger = require('morgan');
var path = require('path');
var cookieParser = require('cookie-parser');

var index = require('./routes/index');

app.use(express.static('public'))
app.use(cors())
app.use(bodyParser.json())
app.use(validator())

app.use(logger('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, './client')));

app.use('/', index);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

app.set('view engine', 'ejs')

app.get('/', (req, res) => {
  res.json({message: 'API Example App'})
});

app.get('/person', (req, res) => {
  Person.findAll().then( (person) =>{
    res.json({person:person})
  })
})

app.post('/person', (req, res) => {
  Person.create({
    username: req.body.username,
    password: req.body.password,
}).then((person)=>{
    res.status(201)
    res.json({person: person})
  })
  req.checkBody('username', 'is required').notEmpty()
  req.getValidationResult()
   .then((validationErrors) =>{
       if(validationErrors.isEmpty()){
        Person.create({
          username: req.body.username,
          password: req.body.password
      }).then((person)=>{
          res.status(201)
          res.json({person: person})
        })
      }else{
        res.status(400)
        res.json({errors: {validations: validationErrors.array()}})
      }
    })
})
module.exports = app
