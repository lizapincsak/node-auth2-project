const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets/index")

function buildToken(user){
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name
    }
    const config = {
      expiresIn: "1d"
    }
    return jwt.sign(payload, JWT_SECRET, config)
  }

  module.exports = {
      buildToken
  }