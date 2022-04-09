const express = require('express');
const router = express.Router();
const createError = require('http-errors');
const User = require('../models/userModel');
const { authSchema } = require('../helpers/validationSchema');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require('../helpers/jwtHelper');
const limter = require('express-rate-limit');

const loginLimiter = limter({
  windowMs: 1 * 60 * 1000,
  max: 1,
});

router.post('/register', async (req, res, next) => {
  try {
    // const { email, password } = req.body;
    // if (!email || !password) throw createError.BadRequest();
    const result = await authSchema.validateAsync(req.body);
    const doesExist = await User.findOne({ email: result.email });
    if (doesExist) {
      throw createError.Conflict(`${result.email} is already registered`);
    }
    const user = new User(result);
    const savedUser = await user.save();
    const accessToken = await signAccessToken(savedUser.id);
    const refreshToken = await signRefreshToken(savedUser.id);
    res.send({ accessToken, refreshToken });
  } catch (error) {
    if (error.isJoi === true) error.status = 422;
    next(error);
  }
});

router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const result = await authSchema.validateAsync(req.body);
    const user = await User.findOne({ email: result.email });
    if (!user) {
      throw createError.NotFound('user not registered');
    }
    const isMatch = await user.isValidPassword(result.password);
    if (!isMatch) throw createError.Unauthorized('username/password not valid');
    const accessToken = await signAccessToken(user.id);
    const refreshToken = await signRefreshToken(user.id);
    res.send({ accessToken, refreshToken });
  } catch (error) {
    if (error.isJoi === true) {
      return next(createError.BadRequest('Invalid username/password'));
    }
    next(error);
  }
});

router.post('/refresh-token', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) throw createError.BadRequest();
    const userId = await verifyRefreshToken(refreshToken);
    const newAccessToken = await signAccessToken(userId);
    const newRefreshToken = await signRefreshToken(userId);
    res.send({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    next(error);
  }
});

router.delete('/logout', async (req, res, next) => {
  res.send('logout route');
});

module.exports = router;
