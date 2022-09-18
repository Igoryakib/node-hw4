const express = require('express');

const authController = require("../controllers/authControllers");
const { auth } = require("../middlewares");

const router = express.Router();

router.post("/register", authController.register);
router.post("/login", authController.login);
router.get("/profile", auth, authController.getMe);
router.get("/logout", auth, authController.logout);

module.exports = router;