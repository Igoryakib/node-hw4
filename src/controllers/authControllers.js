const jwt = require("../utils/jwt");
const { User } = require("../models");

exports.register = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).send("email already in use");
      return;
    }

    const hashedPassword = await User.hashPassword(password);

    const user = await User.create({
      ...req.body,
      email,
      password: hashedPassword,
    });

    const payload = {
      _id: user._id,
    };

    const token = jwt.generate(payload);
    user.token = token;
    await user.save();
    res.status(201).json({
      message: "User successfully created",
      user,
    });
  } catch (error) {
    next(error);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      res.status(401).json({
        message: "user doesn't exist",
      });
      return;
    }

    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      res.status(401).json({
        message: "Email or password is wrong",
      });
      return;
    }

    const payload = {
      _id: user._id,
    };

    const token = jwt.generate(payload);
    user.token = token;
    await user.save();
    res.status(201).json({
      message: "User successfully authorized",
      user,
    });
  } catch (error) {
    next(error);
  }
};

exports.getMe = async (req, res, next) => {
  try {
    res.json(req.user);
  } catch (error) {
    next(error);
  }
};

exports.logout = async (req, res, next) => {
  try {
    req.user.token = null;
    await req.user.save();
    res.json(req.user);
  } catch (error) {
    next(error);
  }
};
