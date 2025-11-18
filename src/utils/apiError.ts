export class ApiError extends Error {
  data: null
  success: boolean
  constructor(
    public statusCode: number,
    message: string,
  ) {
    super(message);
    this.success = false;
    this.data = null;
    Error.captureStackTrace(this, this.constructor);
  }
}
