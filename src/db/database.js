import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";
import logger from "../logger/wiston.logger.js";

/**@type {typeof mongoose || undefined} */
export let dbInstance = undefined;

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URI}/${DB_NAME}`
    );
    dbInstance = connectionInstance;
    logger.info(
      `\n MongoDB connected!! Db Host : ${connectionInstance.connection.host} \n`
    );
  } catch (error) {
    logger.error("MongoDB connection Failed");
    process.exit(1);
  }
};

export default connectDB;
