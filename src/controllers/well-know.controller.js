import { asyncHandler } from "../utils/asyncHandler.js";
import fs from "fs";
import path from "path";
import { importSPKI, exportJWK } from "jose";

const openIdConfiguration = asyncHandler(async (_, res) => {
  return res.status(200).json({
    issuer: `${process.env.DOMAIN}`, // Login & consent
    authorization_endpoint: `${process.env.DOMAIN}/authorize`,
    token_endpoint: `${process.env.DOMAIN}/oauth/token`,
    userinfo_endpoint: `${process.env.DOMAIN}/userinfo`,
    jwks_uri: `${process.env.DOMAIN}/.well-known/jwks.json`,
    revocation_endpoint: `${process.env.DOMAIN}/oauth/revoke`,
    scopes_supported: [
      "openid",
      "profile",
      "offline_access",
      "name",
      "given_name",
      "family_name",
      "nickname",
      "email",
      "email_verified",
      "picture",
      "created_at",
      "identities",
      "phone",
      "address",
    ],
    response_types_supported: [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token",
    ],
    code_challenge_methods_supported: ["S256", "plain"],
    response_modes_supported: ["query", "fragment", "form_post"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
      "private_key_jwt",
    ],
    claims_supported: [
      "sub",
      "fullname",
      "username",
      "email",
      "avatar",
      "role",
      "isEmailVerified",
    ],
    request_uri_parameter_supported: false,
    request_parameter_supported: false,
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
  });
});

const exposePublicKeys = asyncHandler(async (_, res) => {
  const __dirname = path.resolve();
  const PublicKeyPath = path.join(__dirname, "secrets/public.pem");

  const spki = fs.readFileSync(PublicKeyPath, {
    encoding: "utf-8",
  });
  
  const PublicKey = await importSPKI(spki, "RS256");

  const publicKey = await exportJWK(PublicKey);
  publicKey.alg = "RS256";
  publicKey.use = "sig";
  publicKey.kid = process.env.KEY_ID;

  const cachedJwk = {
    keys: [publicKey],
  };

  return res.status(200).json(cachedJwk);
});

// app.get("/authorize", (req, res) => {
//   // Show login page or ask for user consent
//   // On success, generate code and redirect to client
// });

// app.post("/oauth/token", (req, res) => {
//   // Validate grant_type, code/client credentials
//   // Generate JWT access_token and id_token
//   // Return in response
// });

// app.get("/userinfo", authenticateToken, (req, res) => {
//   // req.user se data nikalo aur bhejo
//   res.json({
//     sub: req.user._id,
//     fullname: req.user.fullname,
//     email: req.user.email,
//     role: req.user.role,
//   });
// });

// app.post("/oauth/revoke", (req, res) => {
//   // Token ko database ya memory se delete karo
//   res.status(200).send("Token revoked");
// });

export { openIdConfiguration, exposePublicKeys };
