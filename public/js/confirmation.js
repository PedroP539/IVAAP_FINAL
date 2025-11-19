document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded event fired');

    const toastContainer = document.getElementById('toast-container');

    function showToast(message, confirmCallback, cancelCallback) {
        const toast = document.createElement('div');
        toast.classList.add('toast');
        toast.textContent = message;

        // Create confirm button
        const confirmButton = document.createElement('button');
        confirmButton.textContent = 'Confirmar';
        confirmButton.addEventListener('click', function() {
            confirmCallback();
            toast.classList.remove('show'); // Hide the toast
            setTimeout(() => toastContainer.removeChild(toast), 300); // Remove after animation
        });
        toast.appendChild(confirmButton);

        // Create cancel button
        const cancelButton = document.createElement('button');
        cancelButton.textContent = 'Cancelar';
        cancelButton.addEventListener('click', function() {
            cancelCallback();
            toast.classList.remove('show'); // Hide the toast
            setTimeout(() => toastContainer.removeChild(toast), 300); // Remove after animation
        });
        toast.appendChild(cancelButton);

        toastContainer.appendChild(toast);

        // Show the toast
        setTimeout(() => toast.classList.add('show'), 10);

    }

    document.body.addEventListener('click', function(event) {
        const target = event.target;

        console.log("Clicked element:", target);

        if (target.tagName === 'BUTTON' || target.classList.contains('needs-confirmation')) {
            const button = target;

            console.log("Identified as button:", button);

            if (button.classList.contains('no-confirm')) {
                console.log('Skipping confirmation for button with no-confirm class:', button);
                return;
            }

            // Add the Bootstrap danger button classes for confirmation
            button.classList.add('btn', 'btn-sm', 'btn-danger');

            event.preventDefault();
            console.log('Button clicked, preventing default action:', button);

            showToast('Tem certeza que deseja executar esta ação?',
                function() { // Confirm callback
                    console.log('User confirmed action');
                    button.classList.remove('btn', 'btn-sm', 'btn-danger'); //remove danger class before action

                    // Add success classes
                    button.classList.add('btn', 'btn-sm', 'btn-success');

                    if (button.form) {
                        console.log('Submitting form');
                        try {
                            button.form.submit();
                        } catch (error) {
                            console.error("Error submitting form:", error);
                            button.form.dispatchEvent(new Event('submit', { cancelable: true }));
                        }
                    } else {
                        const onclick = button.getAttribute('onclick');
                        if (onclick) {
                            console.log('Executing onclick:', onclick);
                            try {
                                const fn = new Function(onclick);
                                fn.call(window);
                            } catch (error) {
                                console.error("Error executing onclick:", error);
                                alert("An error occurred while executing the button's action.");
                            }
                        } else {
                            console.log('No form or onclick found for button:', button);
                        }
                    }

                    // Remove success classes (after the action)
                    setTimeout(() => { // Use setTimeout to allow the action to complete visually
                        button.classList.remove('btn', 'btn-sm', 'btn-success');
                    }, 500); // Adjust the timeout as needed

                },
                function() { // Cancel callback
                    console.log('User cancelled action');
                    button.classList.remove('btn', 'btn-sm', 'btn-danger'); //remove danger class after cancel

                    // Add warning classes
                    button.classList.add('btn', 'btn-sm', 'btn-warning');

                    // Remove warning classes (after a short delay)
                    setTimeout(() => { // Use setTimeout to allow the styling to be visible
                        button.classList.remove('btn', 'btn-sm', 'btn-warning');
                    }, 500); // Adjust the timeout as needed
                }
            );

        }
    });
});
