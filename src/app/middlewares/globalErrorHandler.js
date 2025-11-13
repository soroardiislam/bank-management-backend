
const globalErrorHandler = (err, req, res, next) =>{
    console.log("Globar error", err);
    let statusCode = err.statusCode || 500;
    let message = err.message || "Internal Server Error";
    let errorSource = [
        {
            path: "",
            message: "Something went wrong"
        }
    ]
    return res.status(statusCode).json({
        success: false,
        message,
        errorSource,
        err,
        error: err.stack
    })
}

export default globalErrorHandler;
