import winston from "winston";

// Define your severity levels.
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const colors = {
  error: "red",
  warn: "yellow",
  info: "blue",
  http: "magenta",
  debug: "white",
};

winston.addColors(colors);

const level = () => {
  const env = process.env.NODE_ENV || "development";
  const isDevelopment = env === "development";
  return isDevelopment ? "debug" : "warn";
};

const format = winston.format.combine(
  winston.format.timestamp({ format: "DD MMM, YYYY - HH:mm:ss:ms" }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    info => `[${info.timestamp} ${info.level} ${info.message}]`
  )
);

const transports = [
  new winston.transports.Console(),
  new winston.transports.File({
    filename: "log/error.log",
    level: "error",
    colors: "red",
  }),
  new winston.transports.File({
    filename: "log/info.log",
    level: "info",
    colors: "blue",
  }),
  new winston.transports.File({ filename: "log/http.log", level: "http" }),
];

const logger = winston.createLogger({
  level: level(),
  levels,
  format,
  transports,
});

export default logger;
