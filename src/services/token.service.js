import { importPKCS8, SignJWT } from "jose";
import fs from "fs";
import { ApiError } from "../utils/apiError.js";
import path from "path";

const generateAccessAndRefreshTokens = async payload => {
  try {
    const __dirname = path.resolve();
    const PrivateKeyPath = path.join(__dirname, "secrets/private.pem");
    const pkcs8 = fs.readFileSync(PrivateKeyPath, { encoding: "utf-8" });
    const PrivateKey = await importPKCS8(pkcs8, "RS256");

    const now = Math.floor(Date.now() / 1000); // in seconds

    const basePayload = {
      ...payload,
      iss: process.env.DOMAIN,
      iat: now,
    };

    const accessToken = await new SignJWT(basePayload)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt(Math.floor(Date.now() / 1000))
      .setIssuer(process.env.DOMAIN)
      .setExpirationTime("15m")
      .sign(PrivateKey);

    const refreshToken = await new SignJWT(basePayload)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt(Math.floor(Date.now() / 1000))
      .setIssuer(process.env.DOMAIN)
      .setExpirationTime("24h")
      .sign(PrivateKey);

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "An error occurred while generating the access and refresh tokens.",
      error.message
    );
  }
};

export { generateAccessAndRefreshTokens };
