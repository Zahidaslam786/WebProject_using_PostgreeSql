const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // your Gmail address
        pass: process.env.EMAIL_PASS  // your Gmail app password
    }
});

// Email templates
const emailTemplates = {
    welcome: (name) => ({
        subject: 'Welcome to Home Service Hub!',
        html: `
            <h1>Welcome ${name}!</h1>
            <p>Thank you for joining Home Service Hub. We're excited to have you on board!</p>
            <p>You can now start exploring our services and book professionals for your needs.</p>
        `
    }),
    login: (name) => ({
        subject: 'New Login Detected',
        html: `
            <h1>Hello ${name},</h1>
            <p>We detected a new login to your Home Service Hub account.</p>
            <p>If this wasn't you, please secure your account immediately.</p>
        `
    }),
    resetPassword: (name, otp) => ({
        subject: 'Password Reset Request',
        html: `
            <h1>Hello ${name},</h1>
            <p>Your password reset OTP is: <strong>${otp}</strong></p>
            <p>This OTP will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        `
    })
};

module.exports = { transporter, emailTemplates };
