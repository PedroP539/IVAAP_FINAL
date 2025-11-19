// public/js/validateImage.js
const IMAGE_RULES = {
    maxSize: 10 * 1024 * 1024, // 10MB
    minWidth: 800,
    minHeight: 600,
    maxWidth: 4000,
    maxHeight: 4000,
    allowedTypes: ['image/jpeg', 'image/png', 'image/webp']
};

function showError(inputId, message) {
    let error = document.getElementById(inputId + '-error');
    if (!error) {
        error = document.createElement('small');
        error.id = inputId + '-error';
        error.style.color = 'red';
        error.style.display = 'block';
        error.style.marginTop = '5px';
        document.getElementById(inputId).after(error);
    }
    error.textContent = message;
}

function clearError(inputId) {
    const error = document.getElementById(inputId + '-error');
    if (error) error.remove();
}

async function validateFile(file, inputId, previewId) {
    clearError(inputId);
    if (!file) return true;

    // Type
    if (!IMAGE_RULES.allowedTypes.includes(file.type)) {
        showError(inputId, 'Apenas JPG, PNG ou WebP.');
        return false;
    }

    // Size
    if (file.size > IMAGE_RULES.maxSize) {
        showError(inputId, 'Máximo 10MB.');
        return false;
    }

    // Dimensions
    const img = new Image();
    const url = URL.createObjectURL(file);
    return new Promise(resolve => {
        img.onload = () => {
            URL.revokeObjectURL(url);
            const w = img.width, h = img.height;
            if (w < IMAGE_RULES.minWidth || h < IMAGE_RULES.minHeight) {
                showError(inputId, `Mínimo: 800x600px (é ${w}x${h})`);
                resolve(false);
            } else if (w > IMAGE_RULES.maxWidth || h > IMAGE_RULES.maxHeight) {
                showError(inputId, `Máximo: 4000x4000px`);
                resolve(false);
            } else {
                // Update preview
                const preview = document.getElementById(previewId);
                if (preview) {
                    preview.src = url;
                    preview.style.display = 'block';
                }
                resolve(true);
            }
        };
        img.onerror = () => {
            URL.revokeObjectURL(url);
            showError(inputId, 'Imagem corrompida.');
            resolve(false);
        };
        img.src = url;
    });
}

async function validateUrl(url, inputId, previewId) {
    clearError(inputId);
    if (!url) return true;
    if (!url.match(/^https?:\/\/.+/i)) {
        showError(inputId, 'URL inválido.');
        return false;
    }

    try {
        const head = await fetch(url, { method: 'HEAD' });
        const type = head.headers.get('content-type');
        if (!type?.startsWith('image/')) {
            showError(inputId, 'URL não é uma imagem.');
            return false;
        }

        const img = new Image();
        return new Promise(resolve => {
            img.onload = () => {
                const w = img.width, h = img.height;
                if (w < IMAGE_RULES.minWidth || h < IMAGE_RULES.minHeight) {
                    showError(inputId, `Mínimo: 800x600px`);
                    resolve(false);
                } else if (w > IMAGE_RULES.maxWidth || h > IMAGE_RULES.maxHeight) {
                    showError(inputId, `Máximo: 4000x4000px`);
                    resolve(false);
                } else {
                    const preview = document.getElementById(previewId);
                    if (preview) {
                        preview.src = url;
                        preview.style.display = 'block';
                    }
                    resolve(true);
                }
            };
            img.onerror = () => {
                showError(inputId, 'Falha ao carregar imagem.');
                resolve(false);
            };
            img.src = url;
        });
    } catch {
        showError(inputId, 'Erro ao verificar URL.');
        return false;
    }
}