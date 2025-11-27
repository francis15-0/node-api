import express from "express";
import dotenv from "dotenv";
import pool from "./db";
import cors from "cors";
import bcrypt from "bcrypt";
import { url } from "inspector";
import jwt from "jsonwebtoken";
import { authenticateToken } from "./middleware/auth";
dotenv.config();
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());authenticateToken

const salt = 5;
const JWT_SECRET: any = process.env.JWT_SECRET;
app.get("/", (req, res) => {
  res.json({ Message: "Running" });
});

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.json({ message: "Email or password is empty" });
    } else {
      const hash = await bcrypt.hashSync(password, salt);

      const [rows]: any = await pool.query(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        [email, hash]
      );
      console.log(rows);
      if (rows.insertId > 0) {
        return res.json({ message: "Account created Succesfully" });
      }
    }
  } catch (error) {
    console.error("This is the error ", error);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Email or Password ie empty" });
    }

    const [result]: any = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = ?",
      [email]
    );

    const confirm = await bcrypt.compareSync(password, result[0].password_hash);

    if (!confirm) {
      return res.send("Wrong username or password");
    }

    
    const user = result[0];
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);

    return res.status(200).json({
      success: true,
      token: token,
      user: { id: user.id, email: user.email },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Server error during login" });
  }
});


app.get("/profile", authenticateToken, async (req: any, res) => {
  try {
    // req.user is available because of authenticateToken middleware
    const userId = req.user.userId;

    const [result]: any = await pool.query(
      "SELECT id, email FROM users WHERE id = ?",
      [userId]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ user: result[0] });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.listen("3000", () => {
  console.log("The Server is running on port 3000");
});
