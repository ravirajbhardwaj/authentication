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

### 2. Install dependencies

```bash
npm install
```

### 3. Set up environment variables

Create a .env file in the root directory:

```bash
cp .env .env.example
```

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

📥 [Download Collection]()

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
