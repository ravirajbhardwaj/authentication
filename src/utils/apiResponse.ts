class ApiResponse {
  success: boolean
  constructor(
    public statusCode: number,
    public data: any,
    public message: string
  ) {
    this.success = statusCode < 400;
  }
}

export { ApiResponse };
