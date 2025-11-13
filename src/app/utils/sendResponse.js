
const sendResponse = (res, data) =>{
    res.status(data?.statusCode).json({
        success: data?.success,
        message: data?.message,
        data: data?.data ? data?.data : null
    })
}

export default sendResponse;