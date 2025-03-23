module.exports = {
  apps: [
    {
      name: "gts-backend",
      script: "app.js",
      env: {
        PORT: 443,
        DB_USER: "postgres",
        DB_HOST: "database.c5oqyicm6vxg.ap-south-1.rds.amazonaws.com",
        DB_NAME: "gts_system",
        DB_PASSWORD: "Deep.87587",
        DB_PORT: 5432,
        JWT_EXPIRES_IN: "1d",
        JWT_SECRET: "yourSuperSecretKey",
      },
    },
  ],
};
