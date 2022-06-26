var express = require('express');
var router = express.Router();

const User = require("../models/User.model")

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render("index",{User})
});

module.exports = router;
