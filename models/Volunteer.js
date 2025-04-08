import mongoose from 'mongoose';

const volunteerSchema = new mongoose.Schema({
    fullName: String,
    email: String,
    phone: String,
    reason: String,
    ngoId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'NGO',
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

export default mongoose.model('Volunteer', volunteerSchema);