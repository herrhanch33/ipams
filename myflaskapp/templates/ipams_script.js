document.addEventListener('DOMContentLoaded', function() {
    // Function to handle file upload
    function handleFileUpload(event) {
        const file = event.target.files[0];
        const formData = new FormData();
        formData.append('file', file);

        fetch('/import', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            showMessage(data.message);
            if (data.success) {
                location.reload();
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }

    // Function to rollback import
    function rollbackImport() {
        fetch('/rollback', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            showMessage(data.message);
            if (data.success) {
                location.reload();
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }

    // Function to show message
    function showMessage(message) {
        const messageDiv = document.getElementById('message');
        messageDiv.innerText = message;
        messageDiv.style.display = 'block';
        setTimeout(() => {
            messageDiv.style.display = 'none';
        }, 3000);
    }

    // Function to toggle modal visibility
    function toggleModal() {
        const modal = document.getElementById('myModal');
        modal.style.display = modal.style.display === 'block' ? 'none' : 'block';
    }

    // Function to close modal
    function closeModal() {
        const modal = document.getElementById('myModal');
        modal.style.display = 'none';
    }

    // Function to handle bulk delete
    function bulkDelete() {
        const checkboxes = document.querySelectorAll('input[type="checkbox"]:checked');
        const ids = Array.from(checkboxes).map(cb => cb.value);

        if (ids.length > 0) {
            fetch('/bulk_delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ids: ids })
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message);
                if (data.success) {
                    ids.forEach(id => {
                        const row = document.getElementById(`row-${id}`);
                        if (row) {
                            row.remove();
                        }
                    });
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        } else {
            showMessage('No items selected for bulk delete.');
        }
    }

    // Function to confirm delete
    function confirmDelete(id) {
        if (confirm('Are you sure you want to delete this IP address?')) {
            fetch(`/delete/${id}`, {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message);
                if (data.success) {
                    const row = document.getElementById(`row-${id}`);
                    if (row) {
                        row.remove();
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }
    }

    // Function to edit cell
    function editCell(cell) {
        const id = cell.getAttribute('data-id');
        const field = cell.getAttribute('data-field');
        const originalValue = cell.innerText;
        const input = document.createElement('input');
        input.type = 'text';
        input.value = originalValue;
        input.onblur = function() {
            const newValue = input.value;
            if (newValue !== originalValue) {
                const data = { [field]: newValue };

                fetch(`/edit/${id}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                })
                .then(response => response.json())
                .then(data => {
                    showMessage(data.message);
                    if (data.success) {
                        cell.innerText = newValue;
                    } else {
                        cell.innerText = originalValue;
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    cell.innerText = originalValue;
                });
            } else {
                cell.innerText = originalValue;
            }
        };
        input.onkeydown = function(event) {
            if (event.key === 'Enter') {
                input.blur();
            }
        };
        cell.innerText = '';
        cell.appendChild(input);
        input.focus();
    }

    // Attach event listeners
    document.querySelector('.form-button.bulk-delete').addEventListener('click', bulkDelete);
    document.querySelector('.close').addEventListener('click', closeModal);
    document.querySelector('input[type="file"]').addEventListener('change', handleFileUpload);

    window.toggleModal = toggleModal;
    window.closeModal = closeModal;
    window.bulkDelete = bulkDelete;
    window.confirmDelete = confirmDelete;
    window.editCell = editCell;
});
