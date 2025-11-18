import pino, { Logger, stdTimeFunctions } from "pino";
import type { Request, Response } from "express";
import { ApiError } from "../utils/apiError";

const IS_DEV = process.env.NODE_ENV === "development";
const LOG_LEVEL = IS_DEV ? "debug" : "info";

const redact = {
  paths: [
    "password",
    "token",
    "apiKey",
    "authorization",
    "*.password",
    "*.token",
    "req.headers.authorization",
    "req.headers.cookie",
    "creditCard.number",
    "ssn",
  ],
  remove: true,
};

const serializers = {
  err: pino.stdSerializers.err,
  req: (req: Request) =>
    req && req.method ? { method: req.method, url: req.url } : req,
  res: (res: Response) =>
    res && res.statusCode ? { statusCode: res.statusCode } : res,
};

const base = {
  env: process.env.NODE_ENV,
  version: process.env.APP_VERSION || undefined,
};

function createLogger(): Logger {
  const commonOptions = {
    level: LOG_LEVEL,
    serializers,
    redact,
    base,
    timestamp: stdTimeFunctions.isoTime as any,
  };

  if (IS_DEV) {
    return pino(
      commonOptions,
      pino.transport({
        target: "pino-pretty",
        options: {
          colorize: true,
          singleLine: false,
          translateTime: "yyyy-mm-dd HH:MM:ss",
          ignore: "pid,hostname",
        },
      })
    );
  }

  try {
    return pino(commonOptions);
  } catch (err) {
    throw new ApiError(500, "LOGGER FAILED");
  }
}

export const logger: Logger = createLogger();
