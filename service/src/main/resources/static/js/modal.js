const closeButton = document.getElementsByClassName("modal-button")
const modal = document.getElementsByClassName("modal")

function closeModal() {
    modal.classList.remove("show-modal");
}

closeButton.addEventListener("click", () => closeModal());
