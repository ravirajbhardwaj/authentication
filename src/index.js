import dotenv from "dotenv";
import { app } from "./app";
import connectDB from "./db/database.js";

dotenv.config({
  path: "./.env",
});

const PORT = Number(process.env.PORT) || 8080;

async function server() {
  const dbInstance = await connectDB()
  dbInstance
}

server()

connectDB()
  .then(() => {
    app.listen(PORT, () =>
      console.log(
        `⚙️ Server is running at: http://127.0.0.1:${PORT} and Listening on port: ${PORT}`
      )
    );
  })
  .catch(error => console.log("Error while connecting DB", error));
