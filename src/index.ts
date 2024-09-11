import express, { Request, Response, NextFunction } from "express";
import nodemailer from "nodemailer";
import rateLimit from "express-rate-limit";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : [];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        const msg =
          "The CORS policy for this site does not allow access from the specified Origin.";
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    methods: ["POST"],
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Token verification middleware
interface AuthRequest extends Request {
  userId?: string;
}

const verifyToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.headers["x-access-token"] as string;

    if (!token) {
      return res
        .status(403)
        .json({ auth: false, message: "No token provided." });
    }

    jwt.verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
      if (err) {
        return res
          .status(401)
          .json({ auth: false, message: "Failed to authenticate token." });
      }
      req.userId = (decoded as any).id;
      next();
    });
  } catch (error) {
    console.error("Error in token verification:", error);
    return res
      .status(500)
      .json({
        auth: false,
        message: "Internal server error during authentication.",
      });
  }
};

// Nodemailer transporter
let transporter: nodemailer.Transporter;
try {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "465"),
    service: process.env.SMTP_SERVICE,
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
} catch (error) {
  console.error("Failed to create nodemailer transporter:", error);
  process.exit(1);
}

// Input validation middleware
const validateEmailInput = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { to, subject, text } = req.body;

  if (!to || typeof to !== "string" || !to.includes("@")) {
    return res.status(400).json({ message: "Invalid 'to' email address." });
  }

  if (!subject || typeof subject !== "string" || subject.length === 0) {
    return res
      .status(400)
      .json({ message: "Subject is required and must be a non-empty string." });
  }

  if (!text || typeof text !== "string" || text.length === 0) {
    return res
      .status(400)
      .json({
        message:
          "Email body (text) is required and must be a non-empty string.",
      });
  }

  next();
};

app.post(
  "/send-email",
  verifyToken,
  validateEmailInput,
  async (req: AuthRequest, res: Response) => {
    try {
      const { to, subject, text } = req.body;
      const { userId } = req;

      if (!userId) {
        return res
          .status(500)
          .json({ message: "User ID not found in request." });
      }

      const mailOptions = {
        from: `${userId} <${process.env.EMAIL_FROM}>`,
        to,
        subject,
        text,
      };

      await transporter.sendMail(mailOptions);
      res.status(200).json({ message: "Email sent successfully" });
    } catch (error) {
      console.error("Error sending email:", error);
      res.status(500).json({
        message: "Error sending email",
        error: (error as Error).message,
      });
    }
  }
);

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error("Unhandled error:", err);
  res
    .status(500)
    .json({ message: "An unexpected error occurred", error: err.message });
});

// Start the server
try {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
} catch (error) {
  console.error("Failed to start the server:", error);
  process.exit(1);
}
