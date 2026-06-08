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

function getParams() {
    return new URLSearchParams({
        q: document.getElementById("search").value,
        offset
    });
}

/* ---------------- TOASTS ---------------- */

function showToast(message, success = true) {

    const container =
        document.getElementById("toastContainer");

    if (!container) return;

    const toast =
        document.createElement("div");

    toast.className =
        `toast ${success ? "success" : "error"}`;

    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";

        setTimeout(() => {
            toast.remove();
        }, 300);

    }, 2500);
}

/* ---------------- STATUS ---------------- */

function updateStatus(text) {

    const status =
        document.getElementById("status");

    if (status)
        status.textContent = text;

    const statusCard =
        document.getElementById("statusText");

    if (statusCard)
        statusCard.textContent = text;
}

/* ---------------- SEARCH ---------------- */

async function load() {

    if (!authenticated) return;
    if (loading) return;

    loading = true;

    const tbody =
        document.querySelector("tbody");

    const start =
        performance.now();

    updateStatus("SEARCHING");

    tbody.innerHTML = `
        <tr>
            <td colspan="7" style="text-align:center;padding:30px">
                Searching database...
            </td>
        </tr>
    `;

    try {

        const res =
            await fetch("/api/search?" + getParams());

        if (!res.ok) {

            showToast(
                `Search failed (${res.status})`,
                false
            );

            updateStatus("ERROR");

            loading = false;
            return;
        }

        const data =
            await res.json();

        total =
            data.total || 0;

        tbody.innerHTML = "";

        if (
            !data.results ||
            !data.results.length
        ) {

            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align:center;padding:25px">
                        No records found
                    </td>
                </tr>
            `;

            updateStatus("NO RESULTS");

            loading = false;
            return;
        }

        data.results.forEach((c, index) => {

            const tr =
                document.createElement("tr");

            tr.style.opacity = "0";
            tr.style.transform =
                "translateY(6px)";

            tr.innerHTML = `
                <td>${escapeHtml(
                    `${c.FirstName || ""} ${c.LastName || ""}`
                )}</td>

                <td>${escapeHtml(
                    c.LastName || ""
                )}</td>

                <td>${escapeHtml(
                    c.FirstName || ""
                )}</td>

                <td>${escapeHtml(
                    c.Email || ""
                )}</td>

                <td>${escapeHtml(
                    c.Phone || ""
                )}</td>

                <td>${escapeHtml(
                    c.Birthdate || ""
                )}</td>

                <td>${escapeHtml(
                    c.Main_Address__c || ""
                )}</td>
            `;

            tr.onclick =
                () => openDetails(c.id);

            tbody.appendChild(tr);

            requestAnimationFrame(() => {

                setTimeout(() => {

                    tr.style.transition =
                        ".18s ease";

                    tr.style.opacity = "1";
                    tr.style.transform =
                        "translateY(0px)";

                }, index * 4);

            });

        });

        const elapsed =
            Math.round(
                performance.now() - start
            );

        const page =
            Math.floor(
                offset / pageSize
            ) + 1;

        const pages =
            Math.max(
                1,
                Math.ceil(total / pageSize)
            );

        updateStatus(
            `${total.toLocaleString()} records • Page ${page}/${pages} • ${elapsed}ms`
        );

    } catch (err) {

        console.error(err);

        showToast(
            "Database connection error",
            false
        );

        updateStatus("OFFLINE");

    }

    loading = false;
}

/* ---------------- DETAILS ---------------- */

async function openDetails(id) {

    try {

        const modal =
            document.getElementById(
                "detailsModal"
            );

        const content =
            document.getElementById(
                "modalDetails"
            );

        content.innerHTML =
            "<p>Loading...</p>";

        modal.classList.remove(
            "hidden"
        );

        const res =
            await fetch(
                "/api/contact/" + id
            );

        const data =
            await res.json();

        let html =
            "<table>";

        Object.entries(data)
            .forEach(([key, value]) => {

                html += `
                    <tr>
                        <th>${escapeHtml(key)}</th>
                        <td class="copy-cell"
                            data-copy="${escapeHtml(
                                value
                            )}">
                            ${escapeHtml(value)}
                        </td>
                    </tr>
                `;
            });

        html += "</table>";

        content.innerHTML =
            html;

        document
            .querySelectorAll(
                ".copy-cell"
            )
            .forEach(cell => {

                cell.style.cursor =
                    "pointer";

                cell.onclick =
                    async () => {

                        const value =
                            cell.dataset.copy;

                        try {

                            await navigator
                                .clipboard
                                .writeText(
                                    value
                                );

                            showToast(
                                "Copied"
                            );

                        } catch {

                            showToast(
                                "Copy failed",
                                false
                            );

                        }

                    };

            });

    } catch {

        showToast(
            "Failed to load record",
            false
        );

    }

}

/* ---------------- LOGIN ---------------- */

document
    .getElementById("loginForm")
    .addEventListener(
        "submit",
        async e => {

            e.preventDefault();

            const btn =
                e.target.querySelector(
                    "button"
                );

            btn.disabled = true;
            btn.textContent =
                "Authenticating...";

            try {

                const res =
                    await fetch(
                        "/api/login",
                        {
                            method:
                                "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(
                                    {
                                        password:
                                            document.getElementById(
                                                "password"
                                            ).value
                                    }
                                )
                        }
                    );

                const data =
                    await res.json();

                if (
                    data.success
                ) {

                    authenticated =
                        true;

                    document
                        .getElementById(
                            "loginBox"
                        )
                        .classList
                        .add(
                            "hidden"
                        );

                    document
                        .getElementById(
                            "backendUI"
                        )
                        .classList
                        .remove(
                            "hidden"
                        );

                    showToast(
                        "Authenticated"
                    );

                    load();

                } else {

                    document
                        .getElementById(
                            "loginError"
                        )
                        .textContent =
                        data.error ||
                        "Invalid password";

                    showToast(
                        "Access denied",
                        false
                    );

                }

            } catch {

                showToast(
                    "Server unavailable",
                    false
                );

            }

            btn.disabled = false;
            btn.textContent =
                "Login";

        }
    );

/* ---------------- SEARCH ---------------- */

document
    .getElementById("search")
    .addEventListener(
        "input",
        () => {

            clearTimeout(
                searchTimer
            );

            searchTimer =
                setTimeout(
                    () => {

                        offset = 0;
                        load();

                    },
                    600
                );

        }
    );

/* ---------------- PAGINATION ---------------- */

document
    .getElementById("nextBtn")
    .onclick = () => {

    offset += pageSize;
    load();

};

document
    .getElementById("prevBtn")
    .onclick = () => {

    offset =
        Math.max(
            0,
            offset - pageSize
        );

    load();

};

/* ---------------- MODAL ---------------- */

document
    .getElementById("closeModal")
    .onclick = () => {

    document
        .getElementById(
            "detailsModal"
        )
        .classList
        .add("hidden");

};

document
    .getElementById(
        "detailsModal"
    )
    .addEventListener(
        "click",
        e => {

            if (
                e.target.id ===
                "detailsModal"
            ) {

                e.currentTarget
                    .classList
                    .add(
                        "hidden"
                    );

            }

        }
    );

/* ---------------- SHORTCUTS ---------------- */

document
    .addEventListener(
        "keydown",
        e => {

            if (
                e.key === "/"
            ) {

                e.preventDefault();

                const search =
                    document.getElementById(
                        "search"
                    );

                if (search)
                    search.focus();

            }

            if (
                e.key ===
                "Escape"
            ) {

                document
                    .getElementById(
                        "detailsModal"
                    )
                    .classList
                    .add(
                        "hidden"
                    );

            }

        }
    );

/* ---------------- START ---------------- */

updateStatus("READY");
