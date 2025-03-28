import { createHash } from "crypto";
import jwt from "jsonwebtoken";
import { prisma } from "../../extras/prisma";
import { jwtSceretKey } from "../../../environment";
import {
  LogInWithUsernameAndPasswordError,
  SignUpWithUsernameAndPasswordError,
  type LogInWithUsernameAndPasswordResult,
  type SignUpWithUsernameAndPasswordResult,
} from "./authentication-types";

/**
 * Utility function to hash a password using SHA-256.
 */
export const createPasswordHash = ({ password }: { password: string }): string => {
  return createHash("sha256").update(password).digest("hex");
};

/**
 * Utility function to create a JWT token for a user.
 */
const createJWToken = ({ id, username }: { id: string; username: string }): string => {
  const jwtPayload: jwt.JwtPayload = {
    iss: "https://purpleshorts.co.in", // Issuer of the token
    sub: id, // User ID
    username, // Username
  };

  return jwt.sign(jwtPayload, jwtSceretKey, { expiresIn: "30d" }); // Token valid for 30 days
};

/**
 * Handles user sign-up with username and password.
 */
export const signUpWithUsernameAndPassword = async ({
  username,
  password,
  name,
}: {
  username: string;
  password: string;
  name: string;
}): Promise<SignUpWithUsernameAndPasswordResult> => {
  try {
    // Check if the username already exists
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      throw SignUpWithUsernameAndPasswordError.CONFLICTING_USERNAME;
    }

    // Hash the password
    const hashedPassword = createPasswordHash({ password });

    // Create the new user in the database
    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        name,
      },
    });

    // Generate a JWT token for the new user
    const token = createJWToken({ id: user.id, username: user.username });

    return { token, user };
  } catch (error) {
    console.error("Error during sign-up:", error);
    throw SignUpWithUsernameAndPasswordError.UNKNOWN;
  }
};

/**
 * Handles user login with username and password.
 */
export const logInWithUsernameAndPassword = async ({
  username,
  password,
}: {
  username: string;
  password: string;
}): Promise<LogInWithUsernameAndPasswordResult> => {
  // Hash the provided password
  const passwordHash = createPasswordHash({ password });

  // Find the user with the matching username and password
  const user = await prisma.user.findUnique({
    where: {
      username,
      password: passwordHash,
    },
  });

  if (!user) {
    throw LogInWithUsernameAndPasswordError.INCORRECT_USERNAME_OR_PASSWORD;
  }

  // Generate a JWT token for the authenticated user
  const token = createJWToken({ id: user.id, username: user.username });

  return { token, user };
};