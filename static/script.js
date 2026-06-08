let offset = 0;
let total = 0;
let pageSize = 100;
let authenticated = false;
let timer = null;

function escapeHtml(text = "") {
return text
.replaceAll("&","&amp;")
.replaceAll("<","&lt;")
.replaceAll(">","&gt;");
}

function getParams() {
return new URLSearchParams({
q: document.getElementById("search").value,
offset: offset
});
}

async function load() {
if (!authenticated) return;

const status = document.getElementById("status");
status.innerText = "Loading...";

let res = await fetch("/api/search?" + getParams());
let data = await res.json();

total = data.total;

let tbody = document.querySelector("tbody");
tbody.innerHTML = "";

/* 🔥 FIXED FIELD MAPPING */
data.results.forEach(c => {

let tr = document.createElement("tr");

tr.innerHTML = `
<td>${escapeHtml(c.FirstName + " " + c.LastName)}</td>
<td>${escapeHtml(c.LastName)}</td>
<td>${escapeHtml(c.FirstName)}</td>
<td>${escapeHtml(c.Email)}</td>
<td>${escapeHtml(c.Phone)}</td>
<td>${escapeHtml(c.Birthdate)}</td>
<td>${escapeHtml(c.Main_Address__c)}</td>
`;

tr.onclick = () => openDetails(c.id);
tbody.appendChild(tr);

});

let page = Math.floor(offset / pageSize) + 1;
let pages = Math.ceil(total / pageSize);

status.innerText = `Page ${page} / ${pages} • ${total} results`;
}

/* DETAILS */
async function openDetails(id) {
let res = await fetch("/api/contact/" + id);
let data = await res.json();

let html = "<table>";

Object.entries(data).forEach(([k,v]) => {
html += `<tr><th>${k}</th><td>${v}</td></tr>`;
});

html += "</table>";

document.getElementById("modalDetails").innerHTML = html;
document.getElementById("detailsModal").classList.remove("hidden");
}

/* LOGIN */
document.getElementById("loginForm").onsubmit = async (e) => {
e.preventDefault();

let pw = document.getElementById("password").value;

let res = await fetch("/api/login", {
method: "POST",
headers: {"Content-Type":"application/json"},
body: JSON.stringify({password: pw})
});

let data = await res.json();

if (data.success) {
authenticated = true;
document.getElementById("loginBox").classList.add("hidden");
document.getElementById("backendUI").classList.remove("hidden");
load();
} else {
document.getElementById("loginError").innerText = "Wrong password";
}
};

/* SEARCH */
document.getElementById("search").addEventListener("input", () => {
clearTimeout(timer);
timer = setTimeout(() => {
offset = 0;
load();
}, 300);
});

/* PAGINATION */
document.getElementById("nextBtn").onclick = () => {
offset += pageSize;
load();
};

document.getElementById("prevBtn").onclick = () => {
offset = Math.max(0, offset - pageSize);
load();
};

/* CLOSE MODAL */
document.getElementById("closeModal").onclick = () => {
document.getElementById("detailsModal").classList.add("hidden");
};
