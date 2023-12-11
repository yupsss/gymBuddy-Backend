const express = require('express');

const{ signUpUser, loginUser } = require('../constrollers/userController');

const router = express.Router();

router.post('/login',loginUser);
router.post('/signup', signUpUser);

module.exports = router;