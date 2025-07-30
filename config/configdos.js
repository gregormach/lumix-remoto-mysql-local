require('dotenv').config();

module.exports = {
  development: {
    username: process.env.DB_USER_M,
    password: process.env.DB_PASSWORD_M,
    database: process.env.DB_NAME_M,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
    logging: console.log,
  },
};
