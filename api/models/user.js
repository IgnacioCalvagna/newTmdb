const { Model, DataTypes } = require("sequelize");
const db = require("../db/db")
const bcrypt = require("bcrypt");

class User extends Model {
  setHash(password, salt) {
    return bcrypt.hash(password, salt);
  }
}

User.init(
  {
    nombre: {
      type: DataTypes.STRING,
    },
    apellido: {
      type: DataTypes.STRING,
    },
    username: {
      type: DataTypes.STRING,
    },
    email: {
      type: DataTypes.STRING,
      validate: {
        isEmail: true,
        unique: true,
      },
      password: {
        type: DataTypes.STRING,
      },
    },
  },
  {
    sequelize: db,
    modelName: "users",
  }

  User.addHook("beforeCreate", (user) => {
    return bcrypt
      .genSalt(16)
      .then((salt) => {
        user.salt = salt;
        return user.setHash(user.password, salt);
      })
      .then((hash) => {
        user.password = hash;
      });
  })

);

module.exports = User;
