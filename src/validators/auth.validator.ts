import { z } from "zod";

const strongPassword = z
  .string()
  .min(6, { message: "Password must be at least 6 characters long" })
  .max(16, { message: "Password must be at most 16 characters long" })
  .regex(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,}$/, {
    message:
      "Password must contain at least one uppercase letter, one lowercase letter, number and one special character.",
  });

const registerSchema = z.object({
  username: z
    .string()
    .nonempty()
    .max(12, { message: "Fullname must be at most 12 characters long" }),
  email: z
    .string()
    .nonempty()
    .email({ message: "Invalid email address" }),

  password: strongPassword,

  fullname: z
    .string()
    .min(6, { message: "Fullname must be at least 6 characters long" })
    .max(15, { message: "Fullname must be at most 15 characters long" }),
});

const loginSchema = registerSchema
  .pick({
    email: true,
    password: true,
  })
  .extend({
    rememberMe: z.boolean().default(false),
  });

const emailSchema = registerSchema.pick({
  email: true,
});

const changePasswordSchema = z
  .object({
    currentPassword: strongPassword,
    newPassword: strongPassword,
    confirmNewPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: "Confirm password must match the new password",
    path: ["confirmNewPassword"],
  });

const resetPasswordSchema = z
  .object({
    password: strongPassword,
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Confirm password must match the new password",
    path: ["confirmPassword"],
  });

export type RegisterData = z.infer<typeof registerSchema>;
export type LoginData = z.infer<typeof loginSchema>;
export type EmailData = z.infer<typeof emailSchema>;
export type ChangePasswordData = z.infer<typeof changePasswordSchema>;
export type ResetPasswordData = z.infer<typeof resetPasswordSchema>;

export const validateRegister = (data: unknown) => {
  return registerSchema.safeParse(data);
};

export const validateLogin = (data: unknown) => {
  return loginSchema.safeParse(data);
};

export const validateEmail = (data: unknown) => {
  return emailSchema.safeParse(data);
};

export const validateChangePassword = (data: unknown) => {
  return changePasswordSchema.safeParse(data);
};

export const validateResetPassword = (data: unknown) => {
  return resetPasswordSchema.safeParse(data);
};