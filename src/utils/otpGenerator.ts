import errorHandler from "../middlewares/errorHandler.middleware";

export interface IGeneratedOTP {
    otp: string;
    otpExpires: Date;
}

/**
 * @param digits
 * @param minutesValid
 * @returns { otp, otpExpires }
 */

const generateOTP = (digits = 4, minutesValid = 10): IGeneratedOTP => {
    if (digits < 1) throw new Error('Digits must be at least 1');

    const min = Math.pow(10, digits - 1);
    const max = Math.pow(10, digits) - 1;

    const otp = Math.floor(Math.random() * (max - min + 1) + min).toString();
    const otpExpires = new Date(Date.now() + minutesValid * 60 * 1000);

    return { otp, otpExpires };
};

export default generateOTP;