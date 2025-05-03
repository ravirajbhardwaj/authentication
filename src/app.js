import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";

const app = express();

const corsOptions = {
  origin:
    process.env.CORS_ORIGIN === "*" ? "*" : process.env.CORS_ORIGIN?.split(","),
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "12kb" }));
app.use(express.urlencoded({ extended: true, limit: "12kb" }));
app.use(cookieParser());

const __dirname = path.resolve();
app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: 3600,
  })
);

// import all routes
import healthCheckRouter from "./routes/healthcheck.route.js";
import UserRouter from "./routes/user.route.js";

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/users", UserRouter);

export { app };
