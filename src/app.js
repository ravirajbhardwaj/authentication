import express from "express";

const app = express();

// import all routes

import healthCheckRouter from "./routes/healthcheck.route.js";

app.use("/api/v1/healthcheck", healthCheckRouter);

export { app };
