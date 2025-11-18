import dotenv from "dotenv";
import { app } from "./app";
import { logger } from "./logger/pino.logger";

dotenv.config({
  path: "./.env",
});

const PORT = Number(process.env.PORT) || 8080;

app.listen(PORT, () =>
  logger.info(`Server is running at: ${process.env.SERVER_URL}`)
);
