import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import bodyParser from 'body-parser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret from environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'animal-rescue-platform-secret-key-2025';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Import models
import NGO from './models/NGO.js';
import Report from './models/Report.js';
import Animal from './models/Animal.js';
import AdoptionApplication from './models/AdoptionApplication.js';
import Volunteer from './models/Volunteer.js';
import Notification from './models/Notification.js';

// JWT Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.ngo = verified;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// NGO Registration
app.post('/api/ngo/register', async (req, res) => {
  try {
    const { name, email, password, registrationNumber, address, phone } = req.body;
    
    const existingNGO = await NGO.findOne({ email });
    if (existingNGO) {
      return res.status(400).json({ error: 'NGO with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const ngo = new NGO({
      name,
      email,
      password: hashedPassword,
      registrationNumber,
      address,
      phone
    });
    await ngo.save();
    res.status(201).json({ message: 'NGO registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NGO Login
app.post('/api/ngo/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const ngo = await NGO.findOne({ email });
    if (!ngo) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, ngo.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: ngo._id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NGO Dashboard API Routes
app.get('/api/ngo/dashboard/reports', verifyToken, async (req, res) => {
  try {
    const reports = await Report.find().sort({ createdAt: -1 });
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/ngo/dashboard/adoptions', verifyToken, async (req, res) => {
  try {
    console.log('Looking for adoptions with NGO ID:', req.ngo.id);
    
    // Find all adoptions
    const allAdoptions = await AdoptionApplication.find({}).lean();
    console.log('All adoption applications in system:', allAdoptions.length);
    console.log('Sample ngoIds in system:', allAdoptions.slice(0, 3).map(a => a.ngoId));
    
    // Now filter for this specific NGO
    const adoptions = await AdoptionApplication.find({ ngoId: req.ngo.id }).sort({ createdAt: -1 });
    console.log('Found adoptions for this NGO:', adoptions.length);
    
    res.json(adoptions);
  } catch (error) {
    console.error('Error fetching adoptions:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/ngo/dashboard/volunteers', verifyToken, async (req, res) => {
  try {
    const volunteers = await Volunteer.find({ ngoId: req.ngo.id }).sort({ createdAt: -1 });
    res.json(volunteers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/ngo/animals', verifyToken, async (req, res) => {
  try {
    const animals = await Animal.find({ ngoId: req.ngo.id }).sort({ createdAt: -1 });
    res.json(animals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add animal route
app.post('/api/ngo/animals', verifyToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, breed, age, status } = req.body;
    const image = `/uploads/${req.file.filename}`;

    const animal = new Animal({
      name,
      breed,
      age,
      status,
      image,
      ngoId: req.ngo.id
    });

    await animal.save();
    res.status(201).json(animal);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Update adoption status
app.put('/api/ngo/adoptions/:id', verifyToken, async (req, res) => {
  try {
    const adoption = await AdoptionApplication.findOneAndUpdate(
      { _id: req.params.id, ngoId: req.ngo.id },
      { status: req.body.status },
      { new: true }
    );
    res.json(adoption);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update volunteer status
app.put('/api/ngo/volunteers/:id', verifyToken, async (req, res) => {
  try {
    const volunteer = await Volunteer.findOneAndUpdate(
      { _id: req.params.id, ngoId: req.ngo.id },
      { status: req.body.status },
      { new: true }
    );
    res.json(volunteer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Submit report route
app.post('/api/reports', upload.single('photo'), async (req, res) => {
  try {
    const { description, latitude, longitude } = req.body;
    const photo = `/uploads/${req.file.filename}`;

    const report = new Report({
      photo,
      description,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)]
      }
    });

    await report.save();

    // Create notification for all NGOs
    const ngos = await NGO.find({});
    for (const ngo of ngos) {
      const notification = new Notification({
        type: 'report',
        message: 'New animal rescue report submitted',
        ngoId: ngo._id
      });
      await notification.save();
    }

    res.status(201).json(report);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/adopt', async (req, res) => {
  try {
    // Check if petId is valid ObjectId
    if (!req.body.petId || !mongoose.Types.ObjectId.isValid(req.body.petId)) {
      return res.status(400).json({ 
        message: 'Valid Pet ID is required (must be a MongoDB ObjectId)' 
      });
    }
    
    const application = new AdoptionApplication({
      ...req.body
    });
    
    await application.save();

    // Create notification for the specific NGO
    if (req.body.ngoId && mongoose.Types.ObjectId.isValid(req.body.ngoId)) {
      const notification = new Notification({
        type: 'adoption',
        message: `New adoption application for ${req.body.petName}`,
        ngoId: req.body.ngoId
      });
      await notification.save();
    }

    res.status(201).json({ success: true, application });
  } catch (error) {
    console.error('Adoption submission error:', error);
    res.status(500).json({ message: 'Failed to submit application', error: error.message });
  }
});

// Submit volunteer application
app.post('/api/volunteer', async (req, res) => {
  try {
    const volunteer = new Volunteer(req.body);
    await volunteer.save();

    const notification = new Notification({
      type: 'volunteer',
      message: `New volunteer application from ${req.body.fullName}`,
      ngoId: req.body.ngoId
    });
    await notification.save();

    res.status(201).json({ message: 'Volunteer application submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NGO Settings Routes
app.put('/api/ngo/settings', verifyToken, async (req, res) => {
  try {
    const { name, email, phone, address } = req.body;
    const ngo = await NGO.findById(req.ngo.id);
    
    if (!ngo) {
      return res.status(404).json({ error: 'NGO not found' });
    }

    ngo.name = name;
    ngo.email = email;
    ngo.phone = phone;
    ngo.address = address;

    await ngo.save();
    res.json({ message: 'Settings updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/ngo/settings', verifyToken, async (req, res) => {
  try {
    const ngo = await NGO.findById(req.ngo.id).select('-password');
    if (!ngo) {
      return res.status(404).json({ error: 'NGO not found' });
    }
    res.json(ngo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Static Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/ngo/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ngo', 'login.html'));
});

app.get('/ngo/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ngo', 'register.html'));
});

app.get('/ngo/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ngo', 'dashboard.html'));
});

app.get('/volunteer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'volunteer.html'));
});

app.get('/adopt', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'adopt.html'));
});

// Create uploads directory if it doesn't exist
import fs from 'fs';
if (!fs.existsSync('public/uploads')) {
  fs.mkdirSync('public/uploads', { recursive: true });
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


// Get all available animals for adoption
app.get('/api/animals', async (req, res) => {
  try {
      const animals = await Animal.find({ 
          status: 'available' 
      }).populate('ngoId', 'name').lean();
      
      // Format the response to include NGO information
      const formattedAnimals = animals.map(animal => ({
          _id: animal._id,
          name: animal.name,
          breed: animal.breed,
          age: animal.age,
          image: animal.image,
          ngoId: animal.ngoId._id, // Make sure this is the actual MongoDB ID
          ngoName: animal.ngoId.name
      }));
      
      res.json(formattedAnimals);
  } catch (error) {
      console.error('Error fetching animals:', error);
      res.status(500).json({ error: error.message });
  }
});
// Delete animals

app.delete('/api/ngo/animals/:id', verifyToken, async (req, res) => {
  try {
    const animal = await Animal.findOneAndDelete({
      _id: req.params.id,
      ngoId: req.ngo.id
    });
    
    if (!animal) {
      return res.status(404).json({ error: 'Animal not found' });
    }
    
    res.json({ message: 'Animal deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/// Update report status and assign NGO
app.put('/api/ngo/reports/:id', verifyToken, async (req, res) => {
  try {
      const { status } = req.body;
      const ngo = await NGO.findById(req.ngo.id);
      
      // For new assignments (taking action)
      if (status === 'in-progress') {
          const report = await Report.findByIdAndUpdate(
              req.params.id,
              { 
                  status,
                  assignedNGOId: req.ngo.id,
                  assignedNGO: ngo.name
              },
              { new: true }
          );
          res.json(report);
      } 
      // For completing reports - verify the NGO is authorized
      else if (status === 'completed') {
          // First find the report
          const report = await Report.findById(req.params.id);
          
          // Check if the report exists
          if (!report) {
              return res.status(404).json({ error: 'Report not found' });
          }
          
          // Check if the current NGO is the assigned NGO
          if (report.assignedNGOId && report.assignedNGOId.toString() !== req.ngo.id) {
              return res.status(403).json({ 
                  error: 'Unauthorized: Only the assigned NGO can mark this report as complete' 
              });
          }
          
          // If authorized, delete the report
          await Report.findByIdAndDelete(req.params.id);
          res.json({ message: 'Report completed and removed' });
      } 
      // For other status updates
      else {
          const report = await Report.findByIdAndUpdate(
              req.params.id,
              { status },
              { new: true }
          );
          res.json(report);
      }
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});


app.get('/api/ngo/current', verifyToken, async (req, res) => {
  try {
      const ngo = await NGO.findById(req.ngo.id);
      res.json({ _id: ngo._id, name: ngo.name });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});