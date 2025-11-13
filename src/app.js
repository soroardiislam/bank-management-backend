import express from 'express';
import cookieParser from 'cookie-parser';
import cors from "cors";
import globalErrorHandler from './app/middlewares/globalErrorHandler.js';
import router from './app/routes/index.js';
import notFound from './app/middlewares/notFound.js';
const app = express();
import dotenv from "dotenv";


// parsers---------------------------------------------------------
dotenv.config();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:5173', "https://loan-one-mu.vercel.app"],
    credentials: true
}))

// All routes--------------------------------------------------------------
app.use("/api/v1", router);

app.get("/", (req, res) =>{
    res.send("Loan Management System Running");
})

// globar error handler and not found handler--------------------------------------
app.use(globalErrorHandler);
app.use(notFound);

export default app;