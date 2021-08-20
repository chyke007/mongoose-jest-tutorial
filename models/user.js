const mongoose = require("mongoose");
const crypto = require("crypto");
const { Schema } = mongoose;
const UserSchema = new Schema({
  email: {
    type: "String",
    required: true,
  },
  hash: String,
  salt: String,
  name: {
    type: "String",
    required: true,
  },
  phone: String,
  isActive: {
    type: Boolean,
    default: true,
  }
});

const keyLength = 512;
const iterations = 10000;
const digest = "sha512";
const encoding = "hex";

UserSchema.methods.setPassword = function (password) {
  this.salt = crypto.randomBytes(16).toString("hex");
  this.hash = crypto
    .pbkdf2Sync(password, this.salt, iterations, keyLength, digest)
    .toString(encoding);
};

UserSchema.methods.validatePassword = function (password) {
  const hash = crypto
    .pbkdf2Sync(password, this.salt, iterations, keyLength, digest)
    .toString(encoding);
  return this.hash === hash;
};

module.exports = mongoose.model("user", UserSchema);