import multer from "multer";

// memory storage for cloud upload
const storage = multer.memoryStorage();

// file filter
const fileFilter: multer.Options["fileFilter"] = (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) return cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", "Only image files are allowed"));
    cb(null, true);
};

// multer instance
const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

export default upload;