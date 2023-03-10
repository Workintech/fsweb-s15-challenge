const userModel = require("../users/users-model");
const bcrypt = require("bcryptjs");

const payLoadCheck = async function (req, res, next) {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ message: "username ve şifre gereklidir" });
    } else {
      req.encPassword = await bcrypt.hash(req.body.password, 8);
      next();
    }
  } catch (error) {
    next(error);
  }
};

const userNameCheck = async function (req, res, next) {
  try {
    const { username } = req.body;

    let isExistUser = await userModel.getByFilter({ username: username });
    if (isExistUser) {
      res.status(401).json({
        message: "username alınmış",
      });
    } else {
      next();
    }
  } catch (error) {
    next(error);
  }
};

const passwordCheck = async function (req, res, next) {
  try {
    let user = await userModel.getByFilter({ username: req.body.username });
    if (!user) {
      next({
        status: 401,
        message: "geçersiz kriterler",
      });
    } else {
      const { password } = req.body;
      let isTruePassword = bcrypt.compareSync(password, user.password);
      if (!isTruePassword) {
        next({
          status: 401,
          message: "geçersiz kriterler",
        });
      } else {
        req.user = user;
        next();
      }
    }
  } catch (error) {
    next(error);
  }
};

module.exports = {
  payLoadCheck,
  userNameCheck,
  passwordCheck,
};
