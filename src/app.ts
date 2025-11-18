import express from "express";
import cors, { CorsOptions } from "cors";
import cookieParser from "cookie-parser";
import path from "path";

const app = express();

const allowsOrigins = [process.env.CLIENT_URL, "http://localhost:5173"];

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowsOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new ApiError(400, "Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
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
import { errorHandler } from "./middlewares/error.middlerware.js";
import healthCheckRouter from "./routes/healthcheck.route.js";
import UserRouter from "./routes/user.route.js";
import wellKnownRouter from "./routes/well-know.route.js";
import { ApiResponse } from "./utils/apiResponse.js";
import { ApiError } from "./utils/apiError.js";

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/users", UserRouter);
app.use("/.well-known", wellKnownRouter);

app.use(errorHandler);

export { app };
