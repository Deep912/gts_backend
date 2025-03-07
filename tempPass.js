const bcrypt = require("bcrypt");
const workFactor = 8;
var password = "password123";

bcrypt
  .genSalt(workFactor)
  .then((salt) => {
    console.log(`Salt: ${salt}`);
    return bcrypt.hash(password, salt);
  })
  .then((hash) => {
    console.log(`Hash: ${hash}`);
  })
  .catch((err) => console.error(err.message));
