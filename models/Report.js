import mongoose from 'mongoose';

const reportSchema = new mongoose.Schema({
    photo: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    location: {
        type: {
            type: String,
            enum: ['Point'],
            default: 'Point'
        },
        coordinates: {
            type: [Number],
            required: true
        }
    },
    assignedNGOId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'NGO',
        default: null
    },
    assignedNGO: {
        type: String,
        default: null
    },
    status: {
        type: String,
        enum: ['pending', 'in-progress', 'completed'],
        default: 'pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

reportSchema.index({ location: '2dsphere' });

export default mongoose.model('Report', reportSchema);