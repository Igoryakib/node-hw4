const express = require("express");
const volleyball = require("volleyball");
const helmet = require("helmet");
const cors = require("cors");
require("dotenv").config();

require("./config/db");
require("./config/passport");

const apiRouter = require("./routes/apiRouter");

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: false}))
app.use(volleyball);
app.use(helmet());
app.use(
  cors({
    origin: "*",
  })
);

app.use("/api/v1", apiRouter);

app.get("/", (req, res) => {
  res.send("Hello world");
});

module.exports = app;
