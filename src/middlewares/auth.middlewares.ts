import { ApiError } from "../utils/apiError.js";
import asyncHandler from "../utils/asyncHandler";
import { importSPKI, jwtVerify } from "jose";
import path from "path";
import fs from "fs";
import { Request, Response, NextFunction } from "express";

const __dirname = path.resolve();
const PublicKeyPath = path.join(__dirname, "secrets/public.pem");

let cachedPublicKey: CryptoKey | null = null;

async function getPublicKey() {
  if (cachedPublicKey) return cachedPublicKey;

  if (!fs.existsSync(PublicKeyPath)) {
    throw new ApiError(500, `Public key file not found at ${PublicKeyPath}`);
  }

  const spki = fs.readFileSync(PublicKeyPath, { encoding: "utf-8" }).trim();

  // quick sanity check: must be SPKI PEM header
  if (!/^-----BEGIN PUBLIC KEY-----/.test(spki)) {
    // If your file is a certificate, use importX509 instead of importSPKI
    throw new ApiError(
      500,
      `Public key at ${PublicKeyPath} is not SPKI PEM. Ensure it starts with "-----BEGIN PUBLIC KEY-----".`
    );
  }

  // importSPKI returns a Promise<CryptoKey>
  cachedPublicKey = await importSPKI(spki, "RS256");
  return cachedPublicKey;
}

const verifyAccessToken = asyncHandler(async (req: Request, _: Response, next: NextFunction) => {
  const incomingAccessToken =
    req?.cookies?.accessToken ||
    req.header("Authorization")?.replace(/^Bearer\s+/i, "");

  if (!incomingAccessToken) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const pubKey = await getPublicKey();

    const { payload } = await jwtVerify(incomingAccessToken, pubKey, {
      algorithms: ["RS256"],
      issuer: process.env.DOMAIN,
      maxTokenAge: "15m",
      requiredClaims: ["_id", "iss", "iat", "exp"],
    });

    (req as any).user = payload;
    next();
  } catch (error: any) {
    // more helpful logging for debugging
    console.error("Access token verification failed:", error?.message ?? error);
    // Use 401 for invalid token (or 403 if you prefer). Original code used 500.
    throw new ApiError(401, "Invalid or expired access token");
  }
});

const verifyRefreshToken = asyncHandler(async (req: Request, _: Response, next: NextFunction) => {
  const incomingRefreshToken = req?.cookies?.refreshToken || req.body?.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const pubKey = await getPublicKey();

    const { payload } = await jwtVerify(incomingRefreshToken, pubKey, {
      algorithms: ["RS256"],
      issuer: process.env.DOMAIN,
      maxTokenAge: "24h",
      requiredClaims: ["_id", "iss", "iat", "exp"],
      clockTolerance: "5s",
    });

    (req as any).user = payload;
    next();
  } catch (error: any) {
    console.error("Refresh token verification failed:", error?.message ?? error);
    throw new ApiError(403, "Invalid or expired refresh token");
  }
});

const verifyPermission = (roles: string[] = []) =>
  asyncHandler(async (req: Request, _: Response, next: NextFunction) => {
    if (!(req as any).user?._id) {
      throw new ApiError(401, "Unauthorized request");
    }
    if (roles.length === 0 || roles.includes((req as any).user?.role)) {
      next();
    } else {
      throw new ApiError(403, "You are not allowed to perform this action");
    }
  });

export { verifyAccessToken, verifyRefreshToken, verifyPermission };
