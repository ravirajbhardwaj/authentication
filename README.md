# 🔐 Robust Authentication System

A full-featured authentication system built using **Node.js**, **Express**, **MongoDB**, and **Mongoose**, with features like secure password handling, email support, file uploads, and middleware-protected routes.

## 🚀 Features

- 📝 User registration & login
- 🔐 JWT-based authentication
- 🔄 Token refresh & logout
- 🧂 Password hashing using bcrypt
- 📧 Email support using nodemailer
- 📤 File uploads using multer
- 🔒 Protected routes with middleware
- 🎯 Error handling & validation
- ⚙️ Environment-based configuration

---

## ⚙️ Tech Stack

- **Node.js** & **Express**
- **MongoDB** with **Mongoose**
- **JWT** for access control
- **bcryptjs** for password hashing
- **nodemailer** for sending emails
- **multer** for handling file uploads

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

- `private.key`: This will store the private key.
- `public.pub`: This will store the public key.

4. Generate a public and private key pair. You can use the following command to generate them:

   ```bash
   openssl genrsa -out secrets/private.key 2048
   openssl rsa -in secrets/private.key -pubout -out secrets/public.pub
   ```

---

5. This section provides instructions to start the database container using Docker Compose.

   Prerequisites:

   - Ensure Docker and Docker Compose are installed on your system..

   Steps to start the database container:

   1. Open a terminal or command prompt.
   2. Navigate to the directory containing the `compose.yml` file.
   3. Run the following command to start the database container in detached mode:
      ```bash
      docker-compose up -d
      ```
   4. Confirm that the container is running by executing:
      ```bash
      docker ps
      ```
   5. To stop the container, use:
      ```bash
      docker-compose down
      ```

---

6. Use the following commands to run the project:

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

Use the Postman collection below to test all the available APIs:

📥 [Download Collection](https://www.postman.com/ravirajbhardwaaj/ravi-raj/collection/43014457-eeff1890-8ee8-4276-ad6c-4dd40176c874/?action=share&creator=43014457)

Import the collection into Postman and set the environment variables like `server_url`, etc.

## 📄 License

Licensed under the MIT License

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

Feel free to:

- Open issues
- Submit pull requests
- Suggest enhancements

---

## ✨ Author

[Ravi Raj Bhardwaj](http://x.com/ravirajbhrdwaj)

Built with ❤️ to simplify auth flows and speed up backend development.
