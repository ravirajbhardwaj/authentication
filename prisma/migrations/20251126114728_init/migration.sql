-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "LoginType" AS ENUM ('GOOGLE', 'EMAIL');

-- CreateTable
CREATE TABLE "users" (
    "_id" UUID NOT NULL,
    "fullname" VARCHAR(20) NOT NULL,
    "username" VARCHAR(12) NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "avatar" TEXT,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "loginType" "LoginType" NOT NULL DEFAULT 'EMAIL',
    "refreshToken" TEXT,
    "forgotPasswordToken" TEXT,
    "forgotPasswordExpiry" TIMESTAMP(3),
    "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
    "emailVerificationToken" TEXT,
    "emailVerificationExpiry" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "users_refreshToken_key" ON "users"("refreshToken");
