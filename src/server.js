import app from "./app.js";
import mongoose from "mongoose";

let server;

async function main() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    console.log("Database connected");
    const port = process.env.PORT;
    server = app.listen(port, "0.0.0.0", () => {
      console.log(`Server is running on port ${port}`);
    });
  } catch (err) {
    console.log("Error connecting to the database:", err);
  }
}
main();
