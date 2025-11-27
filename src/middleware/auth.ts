import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pool from "../db";
const JWT_SECRET: any = process.env.JWT_SECRET;
interface AuthRequest extends Request {
  user?: {
    userId: number;
    email: string;
  };
}

export function authenticateToken(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    req.user = user;
    next();
  });
}

export async function authApi(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const apikey: any = req.headers["x-api-key"];
    if (!apikey) {
      return res.status(401).send("Api Key required");
    }

    const [rows]: any = await pool.query(
      "SELECT id, user_id, key_hash FROM api_keys"
    );

    let matchedRow = null;

    for (const row of rows) {
      const ok = await bcrypt.compare(apikey, row.key_hash);
      if (ok) {
        matchedRow = row;
        break;
      }
    }

    if (!matchedRow) {
      return res.status(403).send("Invalid API Key");
    }

    const userId = matchedRow.user_id;

    const [userRows]: any = await pool.query(
      "SELECT id, email FROM users WHERE id = ?",
      [userId]
    );
    const user = userRows[0];

    req.user = { userId, email: user?.email };

    next();
  } catch (err) {
    console.error("API key auth error:", err);
    return res.status(500).send("Server error during API key auth");
  }
}
