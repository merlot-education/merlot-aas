
function translate(language) {
    let displayLanguage = document.getElementById("display-language")
    let greeting = document.getElementById("greeting")
    let backButton = document.getElementById("back-button")

    switch (language) {
        case "English":
            displayLanguage.innerText = "English"
            greeting.innerText = "Scan QR code with smartphone"
            backButton.setAttribute("value", "Login via Browser")
            break

        case "Deutsch":
            displayLanguage.innerText = "Deutsch"
            greeting.innerText = "QR-Code mit Smartphone scannen"
            backButton.setAttribute("value", "Anmeldung über Browser")
            break

        case "Français":
            displayLanguage.innerText = "Français"
            greeting.innerText = "Scanner le code QR avec un smartphone"
            backButton.setAttribute("value", "Connexion via le navigateur")
            break

        default:
            displayLanguage.innerText = "English"
            greeting.innerText = "Scan QR code with smartphone"
            backButton.setAttribute("value", "Login via Browser")
            break

    }
}

document.getElementById("Deutsch").addEventListener("click", () => translate("Deutsch"));
document.getElementById("English").addEventListener("click", () => translate("English"));
document.getElementById("Français").addEventListener("click", () => translate("Français"));

