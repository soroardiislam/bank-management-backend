import statusCodes from "http-status";

const notFound = (req, res, next) =>{
    return res.status(statusCodes.NOT_FOUND).json({
        success: false,
        message: "API Not Found!!!",
        error: ""
    })
}

export default notFound;