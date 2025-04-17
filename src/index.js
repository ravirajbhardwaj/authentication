import dotenv from "dotenv";
import { app } from "./app.js";
import connectDB from "./db/database.js";
import logger from "./logger/wiston.logger.js";

dotenv.config({
  path: "./.env",
});

const PORT = Number(process.env.PORT) || 8080;
const majorNodeVersion = +process.env.NODE_VERSION?.split(".")[0] || 0;

const serverStart = () => {
  app.listen(PORT, () =>
    logger.info(
      `⚙️  Server is running at: http://127.0.0.1:${PORT} and Listening on port: ${PORT}`
    )
  );
};

if (majorNodeVersion >= 14) {
  try {
    await connectDB();
    serverStart();
  } catch (error) {
    logger.error("Error while connecting DB", error);
  }
} else {
  connectDB()
    .then(() => {
      serverStart();
    })
    .catch(error => logger.error("Error while connecting DB", error));
}
