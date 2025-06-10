document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initializeStatCounters();
    initializeAvatarUpload();
    initializeBioEditor();
    initializeActivityLoader();
    initializeTimeAgo();
});

// Animate statistics counters
function initializeStatCounters() {
    const counters = document.querySelectorAll('.stat-value');
    counters.forEach(counter => {
        const target = parseInt(counter.dataset.count) || 0;
        animateValue(counter, 0, target, 1000);
    });
}

function animateValue(element, start, end, duration) {
    const range = end - start;
    const increment = end > start ? 1 : -1;
    const stepTime = Math.abs(Math.floor(duration / range));
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        element.textContent = current;
        if (current === end) {
            clearInterval(timer);
        }
    }, stepTime);
}

// Avatar upload handling
function initializeAvatarUpload() {
    const uploadBtn = document.getElementById('avatarUploadBtn');
    const fileInput = document.getElementById('avatarInput');
    const modal = document.getElementById('avatarModal');
    
    if (!uploadBtn || !fileInput || !modal) return;

    uploadBtn.addEventListener('click', () => fileInput.click());
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
            showAvatarPreview(e.target.files[0]);
        }
    });

    // Modal controls
    modal.querySelector('.close').addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#cancelAvatar').addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#saveAvatar').addEventListener('click', () => handleAvatarUpload());
}

function showAvatarPreview(file) {
    const reader = new FileReader();
    const preview = document.querySelector('.avatar-preview');
    const modal = document.getElementById('avatarModal');

    reader.onload = (e) => {
        preview.innerHTML = `<img src="${e.target.result}" alt="Avatar Preview">`;
        modal.style.display = 'block';
    };

    reader.readAsDataURL(file);
}

async function handleAvatarUpload() {
    const fileInput = document.getElementById('avatarInput');
    const formData = new FormData();
    formData.append('avatar', fileInput.files[0]);

    try {
        const response = await fetch('../api/update-avatar.php', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        
        if (result.success) {
            document.querySelector('#profileAvatar img').src = result.avatar_url;
            document.getElementById('avatarModal').style.display = 'none';
            showNotification('Avatar updated successfully', 'success');
        } else {
            throw new Error(result.message);
        }
    } catch (error) {
        showNotification(error.message || 'Failed to update avatar', 'error');
    }
}

// Bio editor functionality
function initializeBioEditor() {
    const editBtn = document.getElementById('editBioBtn');
    const bioContent = document.getElementById('bioContent');
    
    if (!editBtn || !bioContent) return;

    editBtn.addEventListener('click', () => {
        const currentText = bioContent.textContent.trim();
        const textarea = createBioTextarea(currentText);
        const buttonsWrapper = createBioEditButtons();
        
        bioContent.innerHTML = '';
        bioContent.appendChild(textarea);
        bioContent.appendChild(buttonsWrapper);
        textarea.focus();
    });
}

function createBioTextarea(text) {
    const textarea = document.createElement('textarea');
    textarea.className = 'bio-textarea';
    textarea.value = text;
    return textarea;
}

function createBioEditButtons() {
    const wrapper = document.createElement('div');
    wrapper.className = 'bio-edit-buttons';
    
    const saveBtn = document.createElement('button');
    saveBtn.textContent = 'Save';
    saveBtn.className = 'btn btn-primary btn-sm';
    saveBtn.addEventListener('click', () => saveBioChanges());

    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.className = 'btn btn-secondary btn-sm';
    cancelBtn.addEventListener('click', () => cancelBioEdit());

    wrapper.appendChild(saveBtn);
    wrapper.appendChild(cancelBtn);
    return wrapper;
}

async function saveBioChanges() {
    const textarea = document.querySelector('.bio-textarea');
    const newBio = textarea.value.trim();

    try {
        const response = await fetch('../api/update-bio.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ bio: newBio })
        });

        const result = await response.json();
        
        if (result.success) {
            document.getElementById('bioContent').innerHTML = newBio || 'No bio available.';
            showNotification('Bio updated successfully', 'success');
        } else {
            throw new Error(result.message);
        }
    } catch (error) {
        showNotification(error.message || 'Failed to update bio', 'error');
        cancelBioEdit();
    }
}

function cancelBioEdit() {
    const bioContent = document.getElementById('bioContent');
    const originalText = bioContent.dataset.original || 'No bio available.';
    bioContent.innerHTML = originalText;
}

// Activity loader
function initializeActivityLoader() {
    const loadMoreBtn = document.getElementById('loadMoreActivity');
    if (!loadMoreBtn) return;

    let page = 1;
    loadMoreBtn.addEventListener('click', () => loadMoreActivities(++page));
}

async function loadMoreActivities(page) {
    try {
        const response = await fetch(`../api/get-activities.php?page=${page}`);
        const data = await response.json();
        
        if (data.activities && data.activities.length > 0) {
            appendActivities(data.activities);
            if (data.activities.length < 10) {
                document.getElementById('loadMoreActivity').style.display = 'none';
            }
        } else {
            document.getElementById('loadMoreActivity').style.display = 'none';
        }
    } catch (error) {
        showNotification('Failed to load more activities', 'error');
    }
}

function appendActivities(activities) {
    const container = document.querySelector('.activity-list');
    activities.forEach(activity => {
        container.appendChild(createActivityElement(activity));
    });
}

function createActivityElement(activity) {
    const li = document.createElement('li');
    li.className = 'activity-item';
    li.innerHTML = `
        <span class="activity-type">
            <i class="fas fa-${getActivityIcon(activity.type)}"></i>
            ${activity.type}
        </span>
        <span class="activity-content">${activity.description}</span>
        <span class="activity-date" title="${activity.created_at}">
            ${timeago.format(new Date(activity.created_at))}
        </span>
    `;
    return li;
}

// Initialize timeago
function initializeTimeAgo() {
    document.querySelectorAll('.activity-date').forEach(date => {
        const timestamp = date.getAttribute('title');
        if (timestamp) {
            date.textContent = timeago.format(new Date(timestamp));
        }
    });
}

// Utility functions
function getActivityIcon(type) {
    const icons = {
        post: 'comment',
        topic: 'file-alt',
        reply: 'reply',
        like: 'heart',
        follow: 'user-plus',
        default: 'circle'
    };
    return icons[type] || icons.default;
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }, 100);
}