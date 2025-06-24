// static/js/socketHandlers.js

const socket = io();  // Connects to Flask-SocketIO

function showToast(message, bg = 'primary') {
    const toastId = Date.now();
    const toastHtml = `
      <div id="toast-${toastId}" class="toast align-items-center text-white bg-${bg} border-0 mb-2" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="5000">
          <div class="d-flex">
              <div class="toast-body">${message}</div>
              <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
          </div>
      </div>`;
    const container = document.getElementById('toastContainer');
    if (container) {
        container.insertAdjacentHTML('beforeend', toastHtml);
        const toast = new bootstrap.Toast(document.getElementById(`toast-${toastId}`));
        toast.show();
    }
}

// Common events
socket.on('new_query', data => {
    showToast(`New query: ${data.title}`, 'success');
    setTimeout(() => location.reload(), 2000);
});
socket.on('query_edited', data => {
    showToast(`Query #${data.qid} edited: ${data.title}`, 'warning');
    setTimeout(() => location.reload(), 2000);
});
socket.on('query_deleted', data => {
    showToast(`Query #${data.qid} deleted: ${data.title}`, 'danger');
    setTimeout(() => location.reload(), 2000);
});
socket.on('status_update', data => {
    showToast(`Status updated: ${data.title} → ${data.status}`, 'info');
    setTimeout(() => location.reload(), 2000);
});

// Mentor/Admin events
socket.on('query_assigned', data => {
    showToast(`Mentor ${data.mentor_name} accepted: ${data.title}`, 'primary');
    setTimeout(() => location.reload(), 2000);
});
socket.on('query_revoked', data => {
    showToast(`Query revoked: ${data.title}`, 'warning');
    setTimeout(() => location.reload(), 2000);
});
socket.on('solution_submitted', data => {
    showToast(`Resolved: ${data.title}`, 'success');
    setTimeout(() => location.reload(), 2000);
});

// Admin only
socket.on('query_assigned_admin', data => {
    showToast(`Admin assigned mentor ${data.mentor_id} to: ${data.title}`, 'info');
    setTimeout(() => location.reload(), 2000);
});
socket.on('query_revoked_admin', data => {
    showToast(`Admin revoked mentor from: ${data.title}`, 'danger');
    setTimeout(() => location.reload(), 2000);
});
