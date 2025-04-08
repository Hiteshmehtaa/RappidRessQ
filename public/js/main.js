// DOM Elements
const modal = document.getElementById('reportModal');
const btn = document.getElementById('reportBtn');
const span = document.getElementsByClassName('close')[0];
const reportForm = document.getElementById('reportForm');
const preview = document.getElementById('preview');
const cameraFeed = document.getElementById('camera-feed');
const captureBtn = document.getElementById('capture-btn');
const retakeBtn = document.getElementById('retake-btn');
const photoCanvas = document.getElementById('photo-canvas');
const locationStatus = document.getElementById('location-status');
const loading = document.getElementById('loading');
const mapContainer = document.getElementById('map');

let stream = null;
let photoData = null;
let locationData = null;
let map = null;
let marker = null;

// Initialize Leaflet map
function initMap() {
    if (!map) {
        map = L.map('map');
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);
    }
}

// Camera setup
async function setupCamera() {
    try {
        stream = await navigator.mediaDevices.getUserMedia({
            video: {
                facingMode: 'environment',
                width: { ideal: 1280 },
                height: { ideal: 720 }
            },
            audio: false
        });
        cameraFeed.srcObject = stream;
        captureBtn.style.display = 'block';
        retakeBtn.style.display = 'none';
        preview.innerHTML = '';
    } catch (error) {
        console.error('Camera error:', error);
        alert('Unable to access camera. Please make sure you have granted camera permissions.');
    }
}

// Stop camera stream
function stopCamera() {
    if (stream) {
        stream.getTracks().forEach(track => track.stop());
        stream = null;
    }
}

// Modal handlers
btn.onclick = async () => {
    modal.style.display = "block";
    await setupCamera();
    initMap();
    getLocation();
}

span.onclick = () => {
    modal.style.display = "none";
    stopCamera();
}

window.onclick = (event) => {
    if (event.target == modal) {
        modal.style.display = "none";
        stopCamera();
    }
}

// Capture photo
captureBtn.addEventListener('click', () => {
    const context = photoCanvas.getContext('2d');
    photoCanvas.width = cameraFeed.videoWidth;
    photoCanvas.height = cameraFeed.videoHeight;
    context.drawImage(cameraFeed, 0, 0, photoCanvas.width, photoCanvas.height);
    
    photoData = photoCanvas.toDataURL('image/jpeg');
    preview.innerHTML = `<img src="${photoData}" alt="Captured photo">`;
    
    captureBtn.style.display = 'none';
    retakeBtn.style.display = 'block';
    stopCamera();
});

// Retake photo
retakeBtn.addEventListener('click', async () => {
    photoData = null;
    await setupCamera();
});

// Get location
function getLocation() {
    if (navigator.geolocation) {
        locationStatus.style.display = 'block';
        locationStatus.className = 'location-status';
        locationStatus.textContent = 'Getting your location...';
        
        navigator.geolocation.getCurrentPosition(
            (position) => {
                locationData = {
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude
                };
                
                locationStatus.className = 'location-status success';
                locationStatus.textContent = 'Location acquired successfully!';
                
                // Update map with location
                if (map) {
                    const lat = locationData.latitude;
                    const lng = locationData.longitude;
                    map.setView([lat, lng], 15);
                    
                    if (marker) {
                        marker.setLatLng([lat, lng]);
                    } else {
                        marker = L.marker([lat, lng]).addTo(map);
                    }
                    
                    // Add a circle to show accuracy
                    L.circle([lat, lng], {
                        color: '#4CAF50',
                        fillColor: '#4CAF50',
                        fillOpacity: 0.2,
                        radius: 500
                    }).addTo(map);
                }
            },
            (error) => {
                console.error('Location error:', error);
                locationStatus.className = 'location-status error';
                let errorMessage = 'Error getting location. ';
                switch(error.code) {
                    case error.PERMISSION_DENIED:
                        errorMessage += 'Please allow location access in your browser settings.';
                        break;
                    case error.POSITION_UNAVAILABLE:
                        errorMessage += 'Location information is unavailable.';
                        break;
                    case error.TIMEOUT:
                        errorMessage += 'Location request timed out.';
                        break;
                    default:
                        errorMessage += 'Please make sure location services are enabled.';
                }
                locationStatus.textContent = errorMessage;
            },
            {
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 0
            }
        );
    } else {
        locationStatus.className = 'location-status error';
        locationStatus.textContent = 'Geolocation is not supported by your browser.';
    }
}

// Handle form submission
reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    if (!photoData) {
        alert('Please take a photo first.');
        return;
    }
    
    if (!locationData) {
        alert('Please allow location access to continue.');
        return;
    }
    
    loading.style.display = 'block';
    
    try {
        const formData = new FormData();
        
        // Convert base64 to blob
        const response = await fetch(photoData);
        const blob = await response.blob();
        formData.append('photo', blob, 'photo.jpg');
        
        formData.append('description', document.getElementById('description').value);
        formData.append('latitude', locationData.latitude);
        formData.append('longitude', locationData.longitude);

        // Send data to server
        const submitResponse = await fetch('/api/reports', {
            method: 'POST',
            body: formData
        });

        if (submitResponse.ok) {
            alert('Report submitted successfully!');
            modal.style.display = 'none';
            reportForm.reset();
            preview.innerHTML = '';
            locationData = null;
            photoData = null;
        } else {
            throw new Error('Failed to submit report');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        loading.style.display = 'none';
    }
});