# 🔐 Robust Authentication System ![GitHub Repo stars](https://img.shields.io/github/stars/ravirajbhardwaj/authentication?style=social) 

A modern authentication system with features like secure password handling, email support, file uploads, and middleware-protected routes.

## ⚙️ Tech Stack

[![Node.js](https://img.shields.io/badge/Node.js-43853D.svg?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-000000.svg?logo=express&logoColor=white)](https://expressjs.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Prisma](https://img.shields.io/badge/Prisma-3982CE.svg?logo=Prisma&logoColor=white)](https://www.prisma.io/)
[![Neon](https://img.shields.io/badge/Neon-04C7C1.svg?logo=neon&logoColor=white)](https://neon.tech/)
[![Cloudinary](https://img.shields.io/badge/Cloudinary-3448C5.svg?logo=cloudinary&logoColor=white)](https://cloudinary.com/)
[![Nodemailer](https://img.shields.io/badge/Nodemailer-3B82F6.svg?logo=nodemailer&logoColor=white)](https://nodemailer.com/)
[![JWT](https://img.shields.io/badge/JWT-000000.svg?logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![Zod](https://img.shields.io/badge/Zod-3E67B1.svg?logo=zod&logoColor=white)](https://zod.dev/)
[![Pino](https://img.shields.io/badge/Pino-000.svg?logo=pino&logoColor=white)](https://getpino.io/)

---

## 📚 Additional Documentation

### [Authentication Guide](docs/auth.md)

Detailed documentation on how the authentication system works, including middleware usage, token management, and error handling.

### [Learning Resources](docs/learning.md)

A curated list of resources to help you understand the technologies used in this project, such as Node.js, Express, MongoDB, and JWT.

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/ravirajbhardwaj/authentication.git
cd authentication
```

---

### 2. Install dependencies

```bash
npm install
```

---

### 3. Set up environment variables

This project requires setting up environment variables and generating key pairs for authentication.

1. Create a `.env` file in the root directory by copying the `.env.example` file:

```bash
cp .env.example .env
```

2. Create a `secrets` directory at the root of the project:

```bash
mkdir secrets
```

---

3. Inside the `secrets` directory, create two files:

- `private.pem`: This will store the private key.
- `public.pem`: This will store the public key.

4. Generate a public and private key pair. You can use the following command to generate them:
   ✅ 1. Generate Private Key (private.pem)

   ```bash
   openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
   ```

   - -algorithm RSA → We are using RSA algorithm.
   - rsa_keygen_bits:2048 → Sets key size to 2048 bits (standard secure size).
   - This generates `private.pem`.
   - The private key is used to sign the JWTs, ensuring that only the server can create valid tokens.
   - The private key should be kept secret and secure, as it is used to sign the JWTs.

   ✅ 2. Extract Public Key (public.pem) from Private Key

   ```bash
   openssl rsa -pubout -in private.pem -out public.pem
   ```

   - -pubout → Extracts the public key from the private key.
   - -in private.pem → Specifies the input file (private key).
   - -out public.pem → Specifies the output file (public key).
   - This generates `public.pem`.
   - The public key is derived from the private key, allowing you to share it without compromising security.
   - The private key should be kept secret and secure, while the public key can be shared with anyone who needs to verify the JWTs signed with the private key.
   - The public key is used to verify the JWTs, ensuring that they were signed by the server and have not been tampered with.

---

5. Use the following commands to run the project:

   Development mode

   ```bash
   npm run dev
   ```

   Production mode

   ```bash
   npm start
   ```

---

## 📦 Postman Collection

📥 Use the Postman collection below to test all the available APIs:

[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 128px; height: 32px;">](https://god.gw.postman.com/run-collection/43014457-eeff1890-8ee8-4276-ad6c-4dd40176c874?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D43014457-eeff1890-8ee8-4276-ad6c-4dd40176c874%26entityType%3Dcollection%26workspaceId%3D6dea7e89-0c3d-4835-8a6f-f905b8b26190)

Import the collection into Postman and set the environment variables like `server_url`, etc.

---

## ✨ Author & License [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Ravi Raj Bhardwaj](http://x.com/ravirajbhrdwaj)

Built with ❤️ to simplify auth flows and speed up backend development.
