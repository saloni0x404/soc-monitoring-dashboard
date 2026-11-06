const path = require('path');
const { Sequelize } = require('sequelize');

// DB_PATH lets tests (and hosts with a mounted disk) point somewhere else.
const storagePath = process.env.DB_PATH || path.join(__dirname, '..', 'database', 'soc.sqlite');

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: storagePath,
  logging: false,
});

module.exports = sequelize;
