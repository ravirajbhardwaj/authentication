import { Router } from "express";
import {
  openIdConfiguration,
  exposePublicKeys,
} from "../controllers/well-know.controller.js";

const router = Router();

// public routes
router.route("/openid-configuration").get(openIdConfiguration);

router.route("/jwks.json").get(exposePublicKeys);

export default router;
