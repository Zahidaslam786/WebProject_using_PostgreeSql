const { transporter, emailTemplates } = require('../config/nodemailer');

class EmailService {
    static async sendEmail(to, template, data) {
        try {
            const emailContent = emailTemplates[template](data);
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to,
                subject: emailContent.subject,
                html: emailContent.html
            };

            const info = await transporter.sendMail(mailOptions);
            console.log('Email sent:', info.messageId);
            return true;
        } catch (error) {
            console.error('Email sending failed:', error);
            return false;
        }
    }

    static async sendWelcomeEmail(user) {
        return this.sendEmail(user.email, 'welcome', user.name);
    }

    static async sendLoginNotification(user) {
        return this.sendEmail(user.email, 'login', user.name);
    }

    static async sendPasswordResetEmail(user, otp) {
        return this.sendEmail(user.email, 'resetPassword', {
            name: user.name,
            otp
        });
    }
}

module.exports = EmailService;
