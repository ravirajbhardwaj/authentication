import { Request, Response, NextFunction } from "express";
import { logger } from "../logger/pino.logger";
import { Prisma } from "../generated/prisma/client";
import { ApiError } from "../utils/apiError";

const errorHandler = (error: any, req: Request, res: Response, _: NextFunction): void => {
  let apiError: ApiError;

  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    apiError = new ApiError(400, "DATABASE ERROR")
  } else if (error instanceof ApiError) {
    apiError = error
  } else {
    apiError = new ApiError(500, error.message || "INTERNAL SERVER ERROR")
  }

  logger.error({
    path: req.path,
    method: req.method,
    ip: req.ip,
    stack: apiError.stack || ""
  }, apiError.message)

  res.status(apiError.statusCode).json({
    code: apiError.statusCode,
    message: apiError.message,
    data: apiError.data,
    success: apiError.success
  })
}
export { errorHandler };
