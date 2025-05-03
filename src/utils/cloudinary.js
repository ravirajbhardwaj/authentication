import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import logger from "../logger/wiston.logger.js";
import { ApiError } from "../utils/apiError.js";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async localFilePath => {
  try {
    if (!localFilePath) return null;

    const uploadOptions = {
      folder: "auth/uploads",
      use_filename: true,
      unique_filename: true,
      resource_type: "auto",
      overwrite: false,
    };

    const uploadResult = await cloudinary.uploader.upload(
      localFilePath,
      uploadOptions
    );
    logger.info(`File is upload on Cloudinary: ${uploadResult.url}`);

    return uploadResult;
  } catch (error) {
    fs.unlinkSync(localFilePath);
    throw new ApiError(400, "Failed to upload on cloudinary", error);
  }
};

export { uploadOnCloudinary };
