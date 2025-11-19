// LÂMPADA A MORRER – EFEITO FILAMENTO QUEIMADO – IVAAP 2025
let lampIsDead = false;

function triggerLampDeath() {
    if (lampIsDead) return; // só morre uma vez por sessão (ou remove esta linha se quiseres repetir)

    const body = document.body;

    // 1. Começa a piscar como lâmpada velha
    body.classList.add('lamp-flicker');
    
    setTimeout(() => {
        body.classList.remove('lamp-flicker');
        body.classList.add('lamp-dying');
        
        // 2. Escurece gradualmente (3 segundos)
        setTimeout(() => {
            body.classList.add('lamp-dead');
            lampIsDead = true;

            // 3. Opcional: som de lâmpada a queimar (descomenta se quiseres)
            // const audio = new Audio('/sounds/old-bulb-burn.mp3');
            // audio.volume = 0.3;
            // audio.play().catch(() => {});

            console.log("A lâmpada morreu... o IVAAP agora vive na escuridão eterna.");
        }, 3000);
    }, 800);
}

// DISPARA ALEATORIAMENTE ENTRE 15 E 90 SEGUNDOS
function startLampApocalypse() {
    if (lampIsDead) return;
    
    const min = 15000;  // 15 segundos
    const max = 90000;  // 90 segundos
    const randomTime = Math.floor(Math.random() * (max - min + 1)) + min;

    setTimeout(() => {
        triggerLampDeath();
    }, randomTime);
}

// INICIA QUANDO A PÁGINA CARREGA
document.addEventListener('DOMContentLoaded', () => {
    // Primeira ameaça em 10 segundos
    setTimeout(() => {
        console.log("A lâmpada está a aquecer... algo de errado se aproxima.");
    }, 10000);

    startLampApocalypse();
});