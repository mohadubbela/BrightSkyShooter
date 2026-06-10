let offset = 0;
let total = 0;
let pageSize = 100;

let authenticated = false;
let searchTimer = null;
let loading = false;

/* ---------------- HELPERS ---------------- */

function escapeHtml(text = "") {
    return String(text)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
}

function cleanAddress(text = "") {
    return String(text)
        .replace(/<br\s*\/?>/gi, ", ")
        .replace(/\s+/g, " ")
        .trim();
}

function getParams() {
    return new URLSearchParams({
        q: document.getElementById("search").value.trim(),
        offset: offset
    });
}

/* ---------------- TOASTS ---------------- */

function showToast(message, success = true) {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${success ? "success" : "error"}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 2500);
}

/* ---------------- STATUS ---------------- */

function updateStatus(text) {
    const status = document.getElementById("status");
    if (status) status.textContent = text;

    const statusCard = document.getElementById("statusText");
    if (statusCard) statusCard.textContent = text;
}

/* ---------------- SEARCH ---------------- */

async function load() {
    if (!authenticated || loading) return;
    loading = true;

    const tbody = document.querySelector("tbody");
    const start = performance.now();

    updateStatus("SEARCHING...");

    tbody.innerHTML = `
        <tr>
            <td colspan="7" style="text-align:center;padding:60px;color:#888">
                <strong>Searching database...</strong>
            </td>
        </tr>
    `;

    try {
        const res = await fetch("/api/search?" + getParams());
        if (!res.ok) throw new Error("Search failed");

        const data = await res.json();
        total = data.total || 0;
        tbody.innerHTML = "";

        if (!data.results || !data.results.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align:center;padding:60px;color:#888">
                        No records found
                    </td>
                </tr>
            `;
            updateStatus("NO RESULTS");
            loading = false;
            return;
        }

        data.results.forEach((c, index) => {
            const tr = document.createElement("tr");
            tr.style.opacity = "0";
            tr.style.transform = "translateY(6px)";

            // === Verbeterde naam logica ===
            let displayName = "Onbekend";

            if (c.Name && c.Name.trim() !== "") {
                displayName = c.Name;
            } else if (c.FirstName || c.LastName) {
                displayName = `${c.FirstName || ""} ${c.LastName || ""}`.trim();
            } else if (c.firstname || c.lastname) {
                displayName = `${c.firstname || ""} ${c.lastname || ""}`.trim();
            }

            tr.innerHTML = `
                <td>${escapeHtml(displayName)}</td>
                <td>${escapeHtml(c.LastName || c.lastname || "")}</td>
                <td>${escapeHtml(c.FirstName || c.firstname || "")}</td>
                <td>${escapeHtml(c.Email || c.email || "")}</td>
                <td>${escapeHtml(c.Phone || c.phone || "")}</td>
                <td>${escapeHtml(c.Birthdate || c.birthdate || "")}</td>
                <td>${escapeHtml(cleanAddress(c.Main_Address__c || c.main_address__c || ""))}</td>
            `;

            const contactId = c.id || c.Id;
            tr.dataset.id = contactId;
            tr.onclick = () => openDetails(contactId);

            tbody.appendChild(tr);

            requestAnimationFrame(() => {
                setTimeout(() => {
                    tr.style.transition = ".18s ease";
                    tr.style.opacity = "1";
                    tr.style.transform = "translateY(0px)";
                }, index * 4);
            });
        });

        const elapsed = Math.round(performance.now() - start);
        const page = Math.floor(offset / pageSize) + 1;
        const pages = Math.max(1, Math.ceil(total / pageSize));
        updateStatus(`${total.toLocaleString()} records • Page ${page}/${pages} • ${elapsed}ms`);

    } catch (err) {
        console.error(err);
        showToast("Database connection error", false);
        updateStatus("OFFLINE");
    }

    loading = false;
}

/* ---------------- DETAILS ---------------- */

async function openDetails(id) {
    if (!id) return showToast("Invalid contact ID", false);

    const modal = document.getElementById("detailsModal");
    const content = document.getElementById("modalDetails");

    content.innerHTML = "<p style='padding:20px'>Loading contact details...</p>";
    modal.classList.remove("hidden");

    try {
        const res = await fetch(`/api/contact/${id}`);
        if (!res.ok) throw new Error();

        const data = await res.json();
        let html = `<table style="width:100%;border-collapse:collapse">`;

        Object.entries(data).forEach(([key, value]) => {
            if (value == null) value = "";
            if (key.toLowerCase().includes("address")) value = cleanAddress(value);
            html += `
                <tr>
                    <th style="text-align:left;padding:12px 8px;width:180px">${escapeHtml(key)}</th>
                    <td class="copy-cell" data-copy="${escapeHtml(value)}" style="padding:12px 8px;cursor:pointer">
                        ${escapeHtml(value)}
                    </td>
                </tr>`;
        });

        html += "</table>";
        content.innerHTML = html;

        document.querySelectorAll(".copy-cell").forEach(cell => {
            cell.onclick = async () => {
                try {
                    await navigator.clipboard.writeText(cell.dataset.copy);
                    showToast("Copied to clipboard");
                } catch {
                    showToast("Failed to copy", false);
                }
            };
        });
    } catch {
        content.innerHTML = `<p style="color:#ff6666;padding:20px">Failed to load details</p>`;
    }
}

/* ---------------- LOGIN ---------------- */

document.getElementById("loginForm").addEventListener("submit", async function(e) {
    e.preventDefault();

    const btn = e.target.querySelector("button");
    const passwordInput = document.getElementById("password");
    
    btn.disabled = true;
    btn.textContent = "Authenticating...";

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: passwordInput.value })
        });

        const data = await res.json();

        if (data.success) {
            authenticated = true;
            document.getElementById("loginBox").classList.add("hidden");
            document.getElementById("backendUI").classList.remove("hidden");
            showToast("Successfully authenticated");
            load();
        } else {
            document.getElementById("loginError").textContent = data.error || "Invalid password";
            showToast("Access denied", false);
        }
    } catch (err) {
        console.error(err);
        showToast("Server unavailable", false);
    }

    btn.disabled = false;
    btn.textContent = "Login";
});

/* ---------------- OTHER LISTENERS ---------------- */

document.getElementById("search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { offset = 0; load(); }, 500);
});

document.getElementById("nextBtn").onclick = () => { offset += pageSize; load(); };
document.getElementById("prevBtn").onclick = () => { offset = Math.max(0, offset - pageSize); load(); };

document.getElementById("closeModal").onclick = () => {
    document.getElementById("detailsModal").classList.add("hidden");
};

document.getElementById("detailsModal").addEventListener("click", e => {
    if (e.target.id === "detailsModal") {
        e.currentTarget.classList.add("hidden");
    }
});

document.addEventListener("keydown", e => {
    if (e.key === "/" && document.getElementById("search")) {
        e.preventDefault();
        document.getElementById("search").focus();
    }
    if (e.key === "Escape") {
        document.getElementById("detailsModal").classList.add("hidden");
    }
});

updateStatus("READY");
