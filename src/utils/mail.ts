import Mailgen from "mailgen";
import nodemailer from "nodemailer";
import { logger } from "../logger/pino.logger";

interface Options {
  email: string,
  subject: string,
  mailgenContent: Mailgen.Content,
}
/**
 * Sends an email using Mailgen and Nodemailer.
 * @param {{email: string; subject: string; mailgenContent: Mailgen.Content; }} options
 */
const sendMail = async (options: Options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "AuthAPI",
      link: process.env.CLIENT_URL || "https://127.0.1.1:8080",
    },
  });

  const emailTextual = mailGenerator.generate(options?.mailgenContent);
  const emailHtml = mailGenerator.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST || "",
    port: parseInt(process.env.MAILTRAP_SMTP_PORT || "587", 10),
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  } as any
  );

  const mail = {
    from: "mail",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    logger.error(
      `Failed to send email. Please verify your MAILTRAP environment variables ${error}`
    );
  }
};

const emailVerificationMailgenContent = (username: string, verificationUrl: string) => {
  return {
    body: {
      name: username,
      intro: "Thank you for signing up! We're excited to have you on board.",
      action: {
        instructions:
          "Please confirm your email address by clicking the button below:",
        button: {
          color: "#FFA500",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help or have questions? Just reply to this email, and we'll be happy to assist you.",
    },
  };
};

const forgotPasswordMailgenContent = (username: string, passwordResetUrl: string) => {
  return {
    body: {
      name: username,
      intro: "You have requested to reset your password.",
      action: {
        instructions: "To reset your password, please click the button below:",
        button: {
          color: "#FFA500",
          text: "Reset your password",
          link: passwordResetUrl,
        },
      },
      outro:
        "If you did not request a password reset, please ignore this email or contact support if you have questions.",
    },
  };
};

export {
  sendMail,
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
};
