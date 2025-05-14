const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    // ... existing fields ...
    resetPasswordOtp: String,
    resetPasswordExpires: Date
});

// ... existing code ...

module.exports = mongoose.model('User', userSchema);
