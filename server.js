import dotenv from "dotenv";
import express from "express";
import nodemailer from "nodemailer";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import admin from "firebase-admin";
import fs from "fs";

dotenv.config(); 

const app = express();
app.use(cors());
app.use(express.json());

/* ================= FIREBASE SETUP ================= */

// Load service account safely (Node 22 compatible)
const serviceAccount = JSON.parse(
  fs.readFileSync(new URL("./serviceAccountKey.json", import.meta.url))
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://chatab-1444d-default-rtdb.firebaseio.com"
});

const db = admin.database();

/* ================= SMTP SETUP ================= */

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const otpStorage = {};

/* ================= SEND OTP ================= */

app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    otpStorage[email] = {
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000
    };

    await transporter.sendMail({
      from: `"ChatAB Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your OTP Code",
      html: `
        <h2>Welcome to ChatAB 🎉</h2>
        <p>Your OTP:</p>
        <h1>${otp}</h1>
        <p>Valid for 5 minutes.</p>
      `
    });

    res.json({ message: "OTP sent successfully" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error sending OTP" });
  }
});

/* ================= VERIFY OTP ================= */

app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  const stored = otpStorage[email];

  if (!stored) {
    return res.status(400).json({ message: "No OTP found" });
  }

  if (Date.now() > stored.expiresAt) {
    delete otpStorage[email];
    return res.status(400).json({ message: "OTP expired" });
  }

  if (stored.otp !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  delete otpStorage[email];
  res.json({ message: "OTP verified successfully" });
});

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // 🔎 1️⃣ Check Phone Exists
    const phoneSnap = await db.ref("users").child(phone).once("value");

    if (phoneSnap.exists()) {
      return res.status(400).json({ message: "Phone already registered" });
    }

    // 🔎 2️⃣ Check Email Exists
    const emailSnap = await db.ref("users")
      .orderByChild("email")
      .equalTo(email)
      .once("value");

    if (emailSnap.exists()) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // 🔐 Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 💾 Save User
    await db.ref("users").child(phone).set({
      name,
      email,
      phone,
      password: hashedPassword,
      createdAt: Date.now(),
      online: false
    });

    // 🎟 Generate JWT
    const token = jwt.sign(
      { uid: phone, email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: { uid: phone, name, email, phone }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;

    if (!emailOrPhone || !password) {
      return res.status(400).json({
        message: "Email/Phone and password required"
      });
    }

    let snapshot;

    // 🔥 Detect if email or phone
    const isEmail = emailOrPhone.includes("@");
    const field = isEmail ? "email" : "phone";

    snapshot = await db.ref("users")
      .orderByChild(field)
      .equalTo(emailOrPhone)
      .once("value");

    if (!snapshot.exists()) {
      return res.status(400).json({ message: "User not found" });
    }

    let user;
    snapshot.forEach(child => {
      user = child.val();
    });

    // 🔐 Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Wrong password" });
    }

    // 🎟 Generate JWT
    const token = jwt.sign(
      { uid: user.phone, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
}); 

/* ================= START SERVER ================= */

app.listen(5000, () => {
  console.log("OTP Server running on port 5000");
});

export default app;