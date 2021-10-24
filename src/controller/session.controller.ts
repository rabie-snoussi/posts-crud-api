import { Request, Response } from "express";
import get from "lodash/get";
import { validatePassword } from "../service/user.service";
import {
  createAccessToken,
  createSession,
  updateSession,
  findSessions,
  getOneSession,
} from "../service/session.service";
import { sign } from "../utils/jwt.utils";
import config from "config";

export async function createUserSessionHandler(req: Request, res: Response) {
  const user = await validatePassword(req.body);

  if (!user) {
    return res.status(401).send("Invalid username or password");
  }

  const validSession = await getOneSession({ user: user._id, valid: true });

  const session =
    validSession ||
    (await createSession(user._id, req.get("user-agent") || ""));

  const accessToken = createAccessToken({
    user,
    session,
  });

  const refreshToken = sign(session, {
    expiresIn: config.get("refreshTokenTtl"),
  });

  return res.send({ accessToken, refreshToken });
}

export async function invalidateUserSessionHandler(
  req: Request,
  res: Response
) {
  const sessionId = get(req, "user.session");

  await updateSession({ _id: sessionId }, { valid: false });

  return res.sendStatus(200);
}

export async function getUserSessionsHandler(req: Request, res: Response) {
  const userId = get(req, "user._id");

  const sessions = await findSessions({ user: userId, valid: true });

  return res.send(sessions);
}
