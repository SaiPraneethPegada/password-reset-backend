const jwt = require("jsonwebtoken");

const auth = (req, res, next) => {
    try {
        // check access token
        const token = req.header("Authorization");
        const tokenData = jwt.decode(token);

        if (!token) {
            return res.json({
                statusCode: 400,
                message: "Authentication Failed",
            });
        } else if (Math.round(+new Date() / 1000) > tokenData.exp) {
            return res.json({ statusCode: 400, message: "Token expired" });
        } else {
            // validate access token
            jwt.verify(token, process.env.ACCESS_KEY, (err, user) => {
                if (err)
                    return res.json({
                        statusCode: 400,
                        message: "Authentication failed",
                    });
                // success:
                // console.log(user);
                req.user = user;
                next();
            });
        }
    } catch (error) {
        res.json({
            statusCode: 500,
            message: error.message,
        });
    }
};

module.exports = auth;
