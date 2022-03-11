
function translate(language) {
    let displayLanguage = document.getElementById("display-language")
    let greeting = document.getElementById("greeting")
    let signInButton = document.getElementById("sign-in-button")
    let qrBrowserButton = document.getElementById("scan-qr-browser-button")
    let backButton = document.getElementById("back-to-standard-login-button")

    switch (language) {
        case "English":
            displayLanguage.innerText = "English"
            greeting.innerText = "Scan QR code with smartphone"
            signInButton.setAttribute("value", "Sign In")
            qrBrowserButton.setAttribute("value", "Scan QR code with browser")
            backButton.setAttribute("value", "Back to Standard Login")
            break

        case "Deutsch":
            displayLanguage.innerText = "Deutsch"
            greeting.innerText = "QR-Code mit Smartphone scannen"
            signInButton.setAttribute("value", "Anmelden")
            qrBrowserButton.setAttribute("value", "QR-Code mit dem Browser scannen")
            backButton.setAttribute("value", "Zurück zu Standard Login")
            break

        case "Français":
            displayLanguage.innerText = "Français"
            greeting.innerText = "Scanner le code QR avec un mobil"
            signInButton.setAttribute("value", "Connexion")
            qrBrowserButton.setAttribute("value", "Scanner le code QR avec un navigateur")
            backButton.setAttribute("value", "Retour à Connexion standard")
            break

        default:
            displayLanguage.innerText = "English"
            greeting.innerText = "Scan QR code with smartphone"
            signInButton.setAttribute("value", "Sign In")
            qrBrowserButton.setAttribute("value", "Scan QR code with browser")
            backButton.setAttribute("value", "Back to Standard Login")
            break

    }
}

document.getElementById("Deutsch").addEventListener("click", () => translate("Deutsch"));
document.getElementById("English").addEventListener("click", () => translate("English"));
document.getElementById("Français").addEventListener("click", () => translate("Français"));

