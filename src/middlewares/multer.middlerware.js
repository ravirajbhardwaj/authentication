import multer from "multer";
import { randomBytes } from "crypto";
import { ApiError } from "../utils/apiError.js";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/temp");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = randomBytes(16).toString("hex");
    cb(null, file.fieldname + "-" + uniqueSuffix);
  },
});

export const upload = multer({
  storage,
  limits: {
    fieldSize: 100,
    fileSize: 2 * 1024 * 1024, // 2MB
    headerPairs: 1000,
  },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype == "image/png" ||
      file.mimetype == "image/jpg" ||
      file.mimetype == "image/jpeg"
    ) {
      cb(null, true);
    } else {
      return cb(new ApiError(500, "Invalid mime type"));
    }
  },
});
