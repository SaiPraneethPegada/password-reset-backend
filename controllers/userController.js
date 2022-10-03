const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { userDetails } = require("../models/user");
const { hashPassword, hashCompare, createToken } = require("../helpers/auth");
const sendMail = require("../helpers/sendMail");

const userController = {
  signup: async (req, res) => {
    try {
      //get info
      const { userName, email, password } = req.body;

      // check all fields
      if (!userName || !email || !password)
        return res.json({
          statusCode: 400,
          message: "Please fill all fields.",
        });

      if (userName.length < 6) {
        return res.json({
          statusCode: 400,
          message: "User Name must be at least 6 characters long.",
        });
      }

      if (password.length < 8) {
        return res.json({
          statusCode: 400,
          message: "Password must be at least 8 characters long.",
        });
      }

      // check User
      let user = await userDetails.findOne({ email: email });
      let userNameData = await userDetails.findOne({
        userName: userName,
      });

      if (userNameData) {
        res.json({
          statusCode: 400,
          message: "User Name must be Unique",
        });
      } else if (user) {
        res.json({
          statusCode: 400,
          message: "User Already Registered",
        });
      } else {
        //hash password
        let hashed = await hashPassword(req.body.password);

        //create Token
        const newUser = { userName, email, password: hashed };
        const activation_token = createToken.activation(newUser);

        // sendMail
        const url = `https://password-resetting.netlify.app/activate/${activation_token}`;
        sendMail.sendEmailRegister(email, url, "Verify your email");

        // Registration successful
        res.json({
          statusCode: 200,
          message: "Welcome! Please check your email",
          activation_token,
        });
      }
    } catch (error) {
      console.log(error);
      res.json({
        statusCode: 500,
        message: "Internal Server Error",
        error,
      });
    }
  },

  activate: async (req, res) => {
    try {
      //get token
      const { activation_token } = req.body;

      // verify token
      const user = jwt.verify(activation_token, process.env.ACTIVATION_KEY);
      const { userName, email, password } = user;

      //check user
      const check = await userDetails.findOne({ email: email });
      console.log(check);
      // TODO : Implement only email should be unique not the user name.
      if (check)
        return res.json({
          statusCode: 400,
          message: "This email is already registered",
        });

      try {
        const newUser = new userDetails({
          userName,
          email,
          password,
        });
        await newUser.save();
      } catch (error) {
        console.log(error);
        res.json({
          statusCode: 400,
          message: `User Name should be unique ${error.message} `,
          error,
        });
      }

      res.json({
        statusCode: 200,
        message: `Hi ${userName} Your account has been activated, you can now Login`,
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  signin: async (req, res) => {
    try {
      //get credentials
      const { email, password } = req.body;

      // check email
      const user = await userDetails.findOne({ email });
      if (!user)
        return res.json({ statusCode: 400, message: "Not Registered" });

      // check password
      const isMatch = await hashCompare(password, user.password);
      if (!isMatch)
        return res.json({
          statusCode: 400,
          message: "Check your credentials",
        });

      // refresh Token
      const refresh_token = createToken.refresh({ id: user._id });
      res.cookie("_apprefreshtoken", refresh_token, {
        httpOnly: true,
        path: "/auth/access",
        maxAge: 24 * 60 * 60 * 1000,
      });

      //Signin Success
      res.json({
        statusCode: 200,
        message: "Signin Success",
        token: refresh_token,
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  access: async (req, res) => {
    try {
      //refresh Token
      const refresh_token = req.cookies._apprefreshtoken;
      console.log(refresh_token);

      if (!refresh_token)
        return res.json({ statusCode: 400, message: "Please Signin" });

      //validate
      jwt.verify(refresh_token, process.env.REFRESH_KEY, (err, user) => {
        if (err)
          return res.json({
            statusCode: 400,
            message: "Please Signin again.",
          });
        //create access token
        const access_token = createToken.access({ id: user.id }); //getting id from cookie
        console.log(access_token);

        //access success
        return res.json({ statusCode: 200, message: { access_token } });
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  forgot: async (req, res) => {
    try {
      // get email
      const { email } = req.body;

      // check email
      const user = await userDetails.findOne({ email: email });
      if (!user)
        return res.json({
          statusCode: 400,
          message: "Check your email",
        }); // For security reason we should disclose user existence in DB;

      // create access token
      const access_token = createToken.access({
        id: user.id,
        email: user.email,
      });
      console.log(access_token);

      // send email
      const url = `https://password-resetting.netlify.app/reset_password/${access_token}`;
      const name = user.userName;
      sendMail.sendEmailReset(email, url, "Reset your Password", name);

      // success
      res.json({
        statusCode: 200,
        message: "Password reset link sent! please check your mail",
        access_token,
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  reset: async (req, res) => {
    try {
      // get token from headers
      let access_token = req.headers.authorization;
      //console.log(req.headers.authorization);
      // TODO : If access token Expired then alert the user.
      // get password from body.
      const { password } = req.body;

      // hash password
      const salt = await bcrypt.genSalt(12);
      const hashPassword = await bcrypt.hash(password, salt);

      //get user from db
      console.log(req.user);
      const dbUser = await userDetails.findOne({ _id: req.user.id }); // Retrieving user.id from auth middleware.

      // compare new pw and db pw
      const comparison = await bcrypt.compare(password, dbUser.password);

      if (access_token) {
        if (password === "") {
          res.json({ statusCode: 400, message: "Password Required" });
        }

        if (password.length < 8) {
          return res.json({
            statusCode: 400,
            message: "Password must be at least 8 characters long.",
          });
        }

        if (!comparison) {
          // update password
          await userDetails.findOneAndUpdate(
            { _id: req.user.id },
            { $set: { password: hashPassword } }
          );
          // reset success
          res.json({
            statusCode: 200,
            message: "Password reset successfully",
          });
        } else {
          res.json({
            statusCode: 400,
            message: "New Password should be different from old password",
          });
        }
      } else {
        res.json({
          statusCode: 400,
          message: "Invalid Token",
        });
      }
    } catch (error) {
      console.log(error);
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  info: async (req, res) => {
    try {
      // get info (except password)
      const user = await userDetails.findById(req.user.id).select("-password");

      res.json({
        statusCode: 200,
        user,
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  update: async (req, res) => {
    try {
      // get info
      const { userName, avatar } = req.body;

      // update
      await userDetails.findOneAndUpdate(
        { _id: req.user.id },
        { $set: { userName, avatar } }
      );

      // success
      res.json({
        statusCode: 200,
        message: "Updated successfully",
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },

  signout: async (req, res) => {
    try {
      // clear cookie
      res.clearCookie("_apprefreshtoken", { path: "/auth/access" });

      res.json({
        statusCode: 200,
        message: "Signing out successful",
      });
    } catch (error) {
      res.json({
        statusCode: 500,
        message: error.message,
      });
    }
  },
};

module.exports = userController;
