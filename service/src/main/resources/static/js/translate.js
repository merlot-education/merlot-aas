
function translate(language) {
    let displayLanguage = document.getElementById("display-language")
    let greeting = document.getElementById("greeting")
    let loginButton = document.getElementById("sign-in-button")
    let backButton = document.getElementById("go-back-button")

    switch (language) {
        case "English":
            displayLanguage.innerText = "English"
            greeting.innerText = "Sign in to your account"
            loginButton.setAttribute("value", "Sign In")
            backButton.setAttribute("value", "Back")
            break

        case "Deutsch":
            displayLanguage.innerText = "Deutsch"
            greeting.innerText = "Bei Ihrem Konto anmelden"
            loginButton.setAttribute("value", "Anmelden")
            backButton.setAttribute("value", "Zurück")
            break

        case "Français":
            displayLanguage.innerText = "Français"
            greeting.innerText = "Connectez-vous à votre compte "
            loginButton.setAttribute("value", "Connexion")
            backButton.setAttribute("value", "Retourner")
            break

        default:
            displayLanguage.innerText = "English"
            greeting.innerText = "Sign in to your account"
            loginButton.innerText = "Sign In"
            backButton.setAttribute("value", "Back to Keycloak")
            break

    }
}

document.getElementById("Deutsch").addEventListener("click", () => translate("Deutsch"));
document.getElementById("English").addEventListener("click", () => translate("English"));
document.getElementById("Français").addEventListener("click", () => translate("Français"));

