import { createMiddleware } from "hono/factory";
import jwt from "jsonwebtoken";
import { jwtSceretKey } from "../../../environment";

export const tokenMiddleware = createMiddleware<{
  Variables: {
    userId: string;
  };
}>(async (context, next) => {
  const token = context.req.header("token");

  if (!token) {
    return context.json({ error: "Unauthorized" }, 401);
  }

  try {
    const payload = jwt.verify(token, jwtSceretKey) as jwt.JwtPayload;
    const userId = payload.sub;

    if (userId) {
      context.set("userId", userId);
    }

    await next();
  } catch (error) {
    return context.json({ error: "Unauthorized" }, 401);
  }
});
