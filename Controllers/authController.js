const EmailService = require('../services/emailService');
const crypto = require('crypto');

// ... existing code ...

const validateEmail = (email) => {
    const allowedDomains = ['gmail.com', 'outlook.com', 'yahoo.com', 'cfd.nu.edu.pk'];
    const emailDomain = email.split('@')[1];
    return allowedDomains.includes(emailDomain);
};

const authController = {
    async signup(req, res) {
        try {
            const { email, password, name } = req.body;

            if (!email || !password || !name) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            if (!validateEmail(email)) {
                return res.status(400).json({ error: 'Invalid email format. Allowed domains: gmail.com, outlook.com, yahoo.com, cfd.nu.edu.pk.' });
            }

            // ... existing user creation code ...
            
            // Send welcome email
            await EmailService.sendWelcomeEmail(newUser);
            
            res.status(201).json({
                success: true,
                message: 'Registration successful! Please check your email.'
            });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    },

    async login(req, res) {
        try {
            // ... existing login verification code ...
            
            // Send login notification
            await EmailService.sendLoginNotification(user);
            
            res.status(200).json({
                success: true,
                token: token,
                message: 'Login successful!'
            });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    },

    async forgotPassword(req, res) {
        try {
            const { email } = req.body;
            const user = await User.findOne({ email });
            
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Generate OTP
            const otp = crypto.randomInt(100000, 999999).toString();
            
            // Save OTP to user document with expiry
            user.resetPasswordOtp = otp;
            user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
            await user.save();

            // Send password reset email
            await EmailService.sendPasswordResetEmail(user, otp);

            res.status(200).json({
                success: true,
                message: 'Password reset OTP has been sent to your email'
            });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    },

    async resetPassword(req, res) {
        try {
            const { email, otp, newPassword } = req.body;
            const user = await User.findOne({
                email,
                resetPasswordOtp: otp,
                resetPasswordExpires: { $gt: Date.now() }
            });

            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid or expired OTP'
                });
            }

            // Update password
            user.password = newPassword;
            user.resetPasswordOtp = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            res.status(200).json({
                success: true,
                message: 'Password has been reset successfully'
            });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
};

module.exports = authController;
