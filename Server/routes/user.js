const { Router } = require("express");
const User = require("../models/user.js");
const bcrypt = require("bcryptjs");
const { createTokenForUser } = require("../services/authentication.js");
const router = Router();

router.get("/signin", (req, res) => {
  return res.render("signin");
});

router.get("/signup", (req, res) => {
  return res.render("signup");
});

router.post("/signup", async (req, res) => {
  const { fullName, email, password } = req.body;

  const hashed_password = await bcrypt.hash(password, 10);

  const user = await User.create({
    fullName,
    email,
    password: hashed_password,
  });

  res.redirect("/user/signin");
});

router.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    const passCompare = await bcrypt.compare(password, user.password);

    if (passCompare) {
      const token = createTokenForUser(user);

      return res.cookie("token", token).redirect("/");
    } else {
      throw new Error();
    }
  } catch (error) {
    return res.render("signin", {
      error: "Incorrect Email or Password",
    });
  }
});

router.get("/logout", async (req, res) => {
  res.clearCookie("token").redirect("/");
});

module.exports = router;
