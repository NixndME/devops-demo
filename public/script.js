// Load app status from API
async function loadStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        // Update UI with latest info
        document.getElementById('version').textContent = data.version;
        document.getElementById('timestamp').textContent = new Date(data.timestamp).toLocaleString();
        document.getElementById('environment').textContent = data.environment;
        
        // Add highlight animation
        document.querySelector('.stats').classList.add('highlight-change');
        setTimeout(() => {
            document.querySelector('.stats').classList.remove('highlight-change');
        }, 2000);
        
        console.log('✅ Status updated:', data);
    } catch (error) {
        console.error('❌ Failed to load status:', error);
    }
}

// Auto-refresh every 10 seconds
setInterval(loadStatus, 10000);

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    loadStatus();
    console.log('🚀 DevOps Demo App Loaded!');
});
