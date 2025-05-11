import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { importSPKI, jwtVerify } from "jose";
import path from "path";
import fs from "fs";

const __dirname = path.resolve();
const PublicKeyPath = path.join(__dirname, "secrets/public.pem");

const spki = fs.readFileSync(PublicKeyPath, {
  encoding: "utf-8",
});

const PublicKey = await importSPKI(spki, "RS256");

const verifyAccessToken = asyncHandler(async (req, _, next) => {
  const incomingAccessToken =
    req?.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!incomingAccessToken) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const { payload } = await jwtVerify(incomingAccessToken, PublicKey, {
      algorithms: ["RS256"],
      issuer: process.env.DOMAIN,
      maxTokenAge: "15m",
      requiredClaims: ["_id", "iss", "iat", "exp"],
    });

    req.user = payload;
    next();
  } catch (error) {
    console.log(error);
    throw new ApiError(500, "Invalid or expired access token", error.message);
  }
});

const verifyRefreshToken = asyncHandler(async (req, _, next) => {
  const incomingRefreshToken =
    req?.cookies?.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const { payload } = await jwtVerify(incomingRefreshToken, PublicKey, {
      algorithms: ["RS256"],
      issuer: process.env.DOMAIN,
      maxTokenAge: "24h",
      requiredClaims: ["_id", "iss", "iat", "exp"],
      clockTolerance: "5s",
    });

    req.user = payload;
    next();
  } catch (error) {
    throw new ApiError(403, "Invalid or expired refresh token", error.message);
  }
});

const verifyPermission = (roles = []) =>
  asyncHandler(async (req, _, next) => {
    if (!req.user?._id) {
      throw new ApiError(401, "Unauthorized request");
    }
    if (roles.includes(req.user?.role)) {
      next();
    } else {
      throw new ApiError(403, "You are not allowed to perform this action");
    }
  });

export { verifyAccessToken, verifyRefreshToken, verifyPermission };
