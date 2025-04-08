import mongoose from 'mongoose';

const adoptionApplicationSchema = new mongoose.Schema({
    petId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Animal',
        required: true
    },
    petName: String,
    petBreed: String,
    fullName: String,
    email: String,
    phone: String,
    address: String,
    housingType: String,
    hasYard: String,
    hadPets: String,
    petExperience: String,
    hasCurrentPets: String,
    currentPets: String,
    hoursAlone: Number,
    adoptionReason: String,
    hasBreedingExperience: String,
    breedingExperience: String,
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

export default mongoose.model('AdoptionApplication', adoptionApplicationSchema);