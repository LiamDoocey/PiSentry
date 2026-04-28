//Active interval state and chart instance
let trafficChart = null;
let activeInterval = 'hour';

/**
 * Sets the interval for the traffic chart.
 * @param {string} interval - The selected interval: 'hour', 'day', 'week' or 'month'
 */
function setChartInterval(interval){
    activeInterval = interval;

    // Update button active state to highlight the selected interval
    document.querySelectorAll('.interval-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.textContent.toLowerCase() == interval) {
            btn.classList.add('active');
        }
    });
    updateChart();
}


/**
 * Initializes the traffic chart with Chart.js, setting up the datasets and styling.
 * The chart is configured to display three datasets: Benign, flagged Flows, and Threat Intel.
 */
function initChart(){
    const ctx = document.getElementById('traffic-chart').getContext('2d');

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Benign',
                    data: [],
                    borderColor: '#3fb950',
                    backgroundColor: 'rgba(63, 185, 80, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'flagged Flows',
                    data: [],
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248, 81, 73, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Threat Intel',
                    data: [],
                    borderColor: '#d29922',
                    backgroundColor: 'rgba(210, 153, 34, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#8b949e' } }
            },
            scales: {
                x: {
                    ticks: { color: '#8b949e' },
                    grid: { color: '#21262d' }
                },
                y: {
                    ticks: { color: '#8b949e' },
                    grid: { color: '#21262d' },
                    beginAtZero: true
                }
            }
        }
    });
}


/**
 * Fetches traffic history data from the SQLite DB and updates the traffic chart.
 * Updates the chart's labels and datasets based on the selected interval (hour, day, week, month).
 */
function updateChart(){
    fetch(`/api/traffic_history?interval=${activeInterval}`)
        .then(res => res.json())
        .then(data => {
            if (!trafficChart) return;

            // Map the time strings as x-axis labels and each counter as a dataset
            trafficChart.data.labels = data.map(d => d.time);
            trafficChart.data.datasets[0].data = data.map(d => d.benign)
            trafficChart.data.datasets[1].data = data.map(d => d.alerts)
            trafficChart.data.datasets[2].data = data.map(d => d.threats)
            trafficChart.update();
        })
        .catch(err => console.error('Error fetching traffic history: ', err));
}

/**
 * Fetches overall statistics from the SQLite DB and updates the elements in the dashboard.
 */
function updateStats(){
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById('total-flows').textContent = data.total_flows;
            document.getElementById('benign-flows').textContent = data.benign_flows;
            document.getElementById('alert-count').textContent = data.total_alerts;
            document.getElementById('threat-count').textContent = data.threat_intel_matches;
        })
        .catch(err => console.error('Error fetching stats: ', err));
}

/**
 * Fetches the list of alerts from the SQLite DB and updates the alert list in the dashboard.
 * If there are no alerts, it displays a message saying that no alerts have been detected yet.
 * Each alert item is clickable, allowing the user to view more details in a modal.
 */
function updateAlerts() {
    fetch('/api/alerts')
        .then(res => res.json())
        .then(data => {
            const list = document.getElementById('alert-list');

            if (data.length === 0) {
                list.innerHTML = '<p class="no-alerts">No alerts detected yet</p>';
                return;
            }

            list.innerHTML = data.map(alert => `
                <div class="alert-item ${alert.event_type}" onclick="showAlert(${JSON.stringify(alert).replace(/"/g, '&quot;')})">
                    <span class="alert-badge ${alert.event_type}">
                        ${alert.event_type === 'ALERT' ? 'ML ALERT' : 'THREAT INTEL'}
                    </span>
                    <span class="alert-summary">
                        <span>${alert.label}</span> —
                        ${alert.src_ip}:${alert.src_port} → ${alert.dst_ip}:${alert.dst_port}
                    </span>
                    <span class="alert-time">${alert.timestamp}</span>
                </div>
            `).join('');
        })
        .catch(err => console.error('Error fetching alerts:', err));
}

/**
 * Displays the details of a selected alert in a modal.
 * @param {Object} alert - The alert object of the selected alert.
 */
function showAlert(alert) {
    document.getElementById('modal-title').textContent = 
        alert.event_type === 'ALERT' ? 'ML Detection Alert' : 'Threat Intelligence Match';

    document.getElementById('modal-body').innerHTML = `
        <div class="modal-body-row">
            <span class="key">Time</span>
            <span class="value">${alert.timestamp}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Type</span>
            <span class="value">${alert.event_type === 'ALERT' ? 'ML Alert' : 'Threat Intel Match'}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Label</span>
            <span class="value">${alert.label}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Source</span>
            <span class="value">${alert.src_ip}:${alert.src_port}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Destination</span>
            <span class="value">${alert.dst_ip}:${alert.dst_port}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Protocol</span>
            <span class="value">${alert.protocol}</span>
        </div>
        <div class="modal-body-row">
            <span class="key">Confidence</span>
            <span class="value">${alert.confidence ? alert.confidence + '%' : 'N/A'}</span>
        </div>
    `;

    //Show the modal and overlay
    document.getElementById('alert-modal').classList.remove('hidden');
    document.getElementById('modal-overlay').classList.remove('hidden');
}

/**
 * Closes the alert details modal and hides the overlay.
 */
function closeModal() {
    document.getElementById('alert-modal').classList.add('hidden');
    document.getElementById('modal-overlay').classList.add('hidden');
}

/**
 * Opens the alert subscription settings modal.
 */
function openAlertSettings() {
    document.getElementById('alert-settings-modal').classList.remove('hidden');
    document.getElementById('settings-overlay').classList.remove('hidden');
    loadSubscriptions();
}
 
/**
 * Closes the alert subscription settings modal and hides the overlay.
 */
function closeAlertSettings() {
    document.getElementById('alert-settings-modal').classList.add('hidden');
    document.getElementById('settings-overlay').classList.add('hidden');
    hideFeedback();
}
 
/**
 * Fetches the list of subscribed phone numbers from the SQLite DB and updates the subscription list in the alert settings modal.
 */
function loadSubscriptions() {
    fetch('/api/subscriptions')
        .then(res => res.json())
        .then(data => {
            const list = document.getElementById('subscription-list');
            if (data.length === 0) {
                list.innerHTML = '<p class="no-alerts">No subscriptions yet</p>';
                return;
            }
            list.innerHTML = data.map(phone => `
                <div class="subscription-item">
                    <span>${phone}</span>
                    <button class="unsubscribe-btn" onclick="removeSubscription('${phone}')">Remove</button>
                </div>
            `).join('');
        })
        .catch(() => showFeedback('Failed to load subscriptions', 'error'));
}
 
/**
 * Adds a new subscription for the specified phone number to the SQLite DB.
 */
function addSubscription() {
    const phone = document.getElementById('phone-input').value.trim();
    if (!phone) {
        showFeedback('Please enter a phone number', 'error');
        return;
    }
 
    fetch('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone_number: phone })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            document.getElementById('phone-input').value = '';
            showFeedback('Subscribed successfully', 'success');
            loadSubscriptions();
        } else {
            showFeedback('Already subscribed or invalid number', 'error');
        }
    })
    .catch(() => showFeedback('Failed to subscribe', 'error'));
}
 
/**
 * Removes a subscription for the specified phone number from the SQLite DB.
 * @param {string} phone - The phone number to be removed from the subscription list in the SQLite DB.
 */
function removeSubscription(phone) {
    fetch(`/api/subscriptions/${encodeURIComponent(phone)}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                showFeedback('Unsubscribed successfully', 'success');
                loadSubscriptions();
            } else {
                showFeedback('Failed to unsubscribe', 'error');
            }
        })
        .catch(() => showFeedback('Failed to unsubscribe', 'error'));
}
 
/**
 * Displays a feedback message to the user.
 * @param {string} message - The feedback message to be displayed to the user.
 * @param {string} type - The type of feedback, either 'success' or 'error', which determines the styling of the message.
 */
function showFeedback(message, type) {
    const el = document.getElementById('subscription-feedback');
    el.textContent = message;
    el.className = `subscription-feedback ${type}`;
    setTimeout(hideFeedback, 3000);
}
 
/**
 * Hides the feedback message after a short delay, allowing the user to see the message before it disappears.
 */
function hideFeedback() {
    const el = document.getElementById('subscription-feedback');
    el.classList.add('hidden');
}

// Initialize the dashboard by setting up the chart and loading initial data
initChart();
updateStats();
updateChart();

// Set up an interval to refresh the stats, chart, and alerts every 5 seconds to ensure the dashboard displays the most recent data.
setInterval(() => {
    updateStats();
    updateChart();
    updateAlerts();
}, 5000); //Every 5 Seconds

updateAlerts(); //Onload