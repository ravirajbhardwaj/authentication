import crypto from "crypto"
import bcrypt from "bcryptjs";

export const hashPassword = async (password: string) => await bcrypt.hash(password, 10);

export const passwordMatch = async (enteredPassword: string, storedPassword: string) =>
  bcrypt.compare(enteredPassword, storedPassword);

export const createHash = (token: string) =>
  crypto.createHash("sha256").update(token).digest("hex");

export const generateTemporaryToken = () => {
  const unHashedToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = createHash(unHashedToken);
  const tokenExpiry = new Date(Date.now() + 30 * 60 * 1000);

  return { unHashedToken, hashedToken, tokenExpiry };
};