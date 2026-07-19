export function getElement(id) {
    const element = document.getElementById(id);

    if (!element) {
        throw new Error(`Required element not found: #${id}`);
    }

    return element;
}

export function setText(id, value) {
    getElement(id).textContent = value;
}

export function showToast(title, text = "The guided analyst view is ready.") {
    const toast = getElement("toast");

    getElement("toastTitle").textContent = title;
    getElement("toastText").textContent = text;
    toast.classList.add("show");

    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(
        () => toast.classList.remove("show"),
        2400,
    );
}

export function formatTime(dateValue) {
    const date = new Date(dateValue);

    if (Number.isNaN(date.getTime())) {
        return dateValue;
    }

    return date.toLocaleTimeString("en-US", {
        hour: "numeric",
        minute: "2-digit",
    });
}

export function escapeHtml(value) {
    const temporaryElement = document.createElement("div");
    temporaryElement.textContent = String(value ?? "");
    return temporaryElement.innerHTML;
}
