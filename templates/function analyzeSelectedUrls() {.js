 // URL Selection Modal Variables
let allUrls = [];
let selectedUrls = new Set();
let filteredUrls = [];

// Initialize select URLs button event listener
document.addEventListener("DOMContentLoaded", function () {
    const selectUrlsBtn = document.getElementById('selectUrlsBtn');
    if (selectUrlsBtn) {
        selectUrlsBtn.addEventListener('click', function() {
            const url = document.getElementById('websiteUrl').value.trim();
            if (!isValidUrl(url)) {
                alert("Please enter a valid website URL first.");
                return;
            }
            openUrlSelectionModal(url);
        });
    }

    // Add modal close event listeners
    document.getElementById("urlSelectionModal").addEventListener("click", function(e) {
        if (e.target === this) {
            closeUrlSelectionModal();
        }
    });

    document.addEventListener("keydown", function(e) {
        if (e.key === "Escape") {
            closeUrlSelectionModal();
        }
    });
});

function openUrlSelectionModal(url) {
    const modal = document.getElementById("urlSelectionModal");
    modal.style.display = "flex";
    
    // Show loading, hide other sections
    document.getElementById("modalLoading").style.display = "block";
    document.getElementById("modalUrls").style.display = "none";
    document.getElementById("modalError").style.display = "none";
    
    // Clear previous selections
    selectedUrls.clear();
    document.getElementById("selectAllUrls").checked = false;
    document.getElementById("urlSearch").value = "";
    
    // Fetch sitemap URLs
    fetchSitemapUrls(url);
}

function closeUrlSelectionModal() {
    document.getElementById("urlSelectionModal").style.display = "none";
}

function fetchSitemapUrls(url) {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    const formData = new FormData();
    formData.append('csrf_token', csrfToken);
    formData.append('url', url);
    
    fetch("/analyze_with_selection", {
        method: "POST",
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.text();
    })
    .then(html => {
        // Parse the HTML response
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Try to find URLs in different ways
        let urlsFound = [];
        
        // Method 1: Check for URL checkboxes
        const urlCheckboxes = doc.querySelectorAll('input[name="selected_urls"]');
        if (urlCheckboxes.length > 0) {
            urlsFound = Array.from(urlCheckboxes).map(cb => cb.value);
        }
        
        // Method 2: Check for data in JSON format
        const jsonScripts = doc.querySelectorAll('script[type="application/json"]');
        jsonScripts.forEach(script => {
            try {
                const data = JSON.parse(script.textContent);
                if (data.urls && Array.isArray(data.urls)) {
                    urlsFound = data.urls;
                }
            } catch (e) {
                // Not valid JSON, skip
            }
        });
        
        // Method 3: Check for list items with URLs
        if (urlsFound.length === 0) {
            const urlElements = doc.querySelectorAll('a[href], li, .url-item');
            urlElements.forEach(el => {
                const text = el.textContent.trim();
                if (text && (text.startsWith('http://') || text.startsWith('https://'))) {
                    urlsFound.push(text);
                } else if (el.hasAttribute('href')) {
                    const href = el.getAttribute('href');
                    if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
                        urlsFound.push(href);
                    }
                }
            });
        }
        
        // Remove duplicates
        urlsFound = [...new Set(urlsFound)];
        
        if (urlsFound.length > 0) {
            allUrls = urlsFound;
            showUrlsInModal();
        } else {
            // Try alternative endpoint
            return fetchAlternativeEndpoint(url);
        }
    })
    .catch(error => {
        console.error("Error fetching sitemap:", error);
        fetchAlternativeEndpoint(url);
    });
}

function fetchAlternativeEndpoint(url) {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    
    fetch("/get_sitemap_urls", {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.urls && data.urls.length > 0) {
            allUrls = data.urls;
            showUrlsInModal();
        } else {
            throw new Error(data.message || "No URLs found in sitemap");
        }
    })
    .catch(error => {
        console.error("Alternative endpoint error:", error);
        showErrorInModal("Failed to fetch URLs. Please check if the website has a valid sitemap or try a different website.");
    });
}

function showUrlsInModal() {
    document.getElementById("modalLoading").style.display = "none";
    document.getElementById("modalUrls").style.display = "block";
    
    // Update URL count
    document.getElementById("urlCount").textContent = allUrls.length;
    
    // Initialize filtered URLs
    filteredUrls = [...allUrls];
    
    // Display URLs
    displayUrls();
    
    // Update analyze button state
    updateAnalyzeButton();
}

function showErrorInModal(message) {
    document.getElementById("modalLoading").style.display = "none";
    document.getElementById("modalError").style.display = "block";
    document.getElementById("errorMessage").textContent = message;
}

function displayUrls() {
    const urlList = document.getElementById("urlList");
    urlList.innerHTML = '';
    
    if (filteredUrls.length === 0) {
        urlList.innerHTML = '<div class="no-urls-message">No URLs found matching your search.</div>';
        return;
    }
    
    filteredUrls.forEach((url, index) => {
        const urlItem = document.createElement("div");
        urlItem.className = "url-item";
        
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.id = `url-${index}`;
        checkbox.value = url;
        checkbox.checked = selectedUrls.has(url);
        checkbox.onchange = function() {
            if (this.checked) {
                selectedUrls.add(url);
            } else {
                selectedUrls.delete(url);
                document.getElementById("selectAllUrls").checked = false;
            }
            updateAnalyzeButton();
        };
        
        const urlText = document.createElement("div");
        urlText.className = "url-text";
        urlText.textContent = url;
        
        urlItem.appendChild(checkbox);
        urlItem.appendChild(urlText);
        urlList.appendChild(urlItem);
    });
    
    // Update select all checkbox
    const allFilteredSelected = filteredUrls.length > 0 && 
        filteredUrls.every(url => selectedUrls.has(url));
    document.getElementById("selectAllUrls").checked = allFilteredSelected;
}

function toggleSelectAll() {
    const selectAllCheckbox = document.getElementById("selectAllUrls");
    
    if (selectAllCheckbox.checked) {
        // Add all filtered URLs to selection
        filteredUrls.forEach(url => selectedUrls.add(url));
    } else {
        // Remove all filtered URLs from selection
        filteredUrls.forEach(url => selectedUrls.delete(url));
    }
    
    displayUrls();
    updateAnalyzeButton();
}

function filterUrls() {
    const searchTerm = document.getElementById("urlSearch").value.toLowerCase();
    
    if (searchTerm) {
        filteredUrls = allUrls.filter(url => 
            url.toLowerCase().includes(searchTerm)
        );
    } else {
        filteredUrls = [...allUrls];
    }
    
    document.getElementById("urlCount").textContent = `${filteredUrls.length} of ${allUrls.length}`;
    displayUrls();
}

function updateAnalyzeButton() {
    const analyzeBtn = document.getElementById("analyzeSelectedBtn");
    analyzeBtn.disabled = selectedUrls.size === 0;
    analyzeBtn.textContent = `Analyze Selected (${selectedUrls.size})`;
}

function analyzeSelectedUrls() {
    if (selectedUrls.size === 0) {
        alert("Please select at least one URL to analyze.");
        return;
    }
    
    const originalUrl = document.getElementById('websiteUrl').value.trim();
    
    // Close modal
    closeUrlSelectionModal();
    
    // Show progress container
    const processingContainer = document.getElementById("processingContainer");
    const progressText = document.getElementById("progressText");
    const currentUrlElement = document.getElementById("currentUrl");
    
    if (processingContainer) {
        processingContainer.style.display = "block";
        progressText.textContent = `Preparing to analyze ${selectedUrls.size} selected URLs...`;
        currentUrlElement.textContent = "";
    }
    
    // Submit selected URLs to backend
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    const formData = new FormData();
    formData.append('csrf_token', csrfToken);
    
    // Add selected URLs
    selectedUrls.forEach(url => {
        formData.append('selected_urls', url);
    });
    
    formData.append('original_url', originalUrl);
    
    // Try different endpoints for selected URL analysis
    const endpoints = [
        "/analyze_selected",
        "/analyze_selected_urls",
        "/start_selected_analysis"
    ];
    
    let currentEndpointIndex = 0;
    
    function tryNextEndpoint() {
        if (currentEndpointIndex >= endpoints.length) {
            // All endpoints failed
            if (progressText) {
                progressText.textContent = "Failed to start analysis. Please try again or contact support.";
            }
            setTimeout(() => {
                if (processingContainer) {
                    processingContainer.style.display = "none";
                }
            }, 3000);
            return;
        }
        
        const endpoint = endpoints[currentEndpointIndex];
        currentEndpointIndex++;
        
        fetch(endpoint, {
            method: "POST",
            body: formData
        })
        .then(response => {
            if (response.redirected) {
                // If redirecting, follow the redirect
                window.location.href = response.url;
                return null;
            }
            return response.text();
        })
        .then(data => {
            if (data === null) return; // Redirect handled
            
            try {
                const jsonData = JSON.parse(data);
                if (jsonData.success) {
                    if (jsonData.job_id) {
                        // Start monitoring progress
                        currentJobId = jsonData.job_id;
                        if (window.setupEventSource) {
                            setupEventSource(currentJobId);
                        }
                    } else if (jsonData.redirect_url) {
                        window.location.href = jsonData.redirect_url;
                    }
                } else {
                    // Try next endpoint
                    tryNextEndpoint();
                }
            } catch (e) {
                // Not JSON, could be HTML or other response
                console.log("Response is not JSON, trying next endpoint");
                tryNextEndpoint();
            }
        })
        .catch(error => {
            console.error(`Error with endpoint ${endpoint}:`, error);
            tryNextEndpoint();
        });
    }
    
    // Start trying endpoints
    tryNextEndpoint();
}

// Helper function to validate URLs
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}
    </script>