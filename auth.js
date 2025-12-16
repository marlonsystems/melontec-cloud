const API = "https://DEIN-BACKEND.onrender.com/api";

function login() {
  fetch(`${API}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email.value,
      password: password.value
    })
  })
  .then(r => r.json())
  .then(d => {
    if (d.token) {
      localStorage.setItem("token", d.token);
      location.href = "index.html";
    } else alert("Login fehlgeschlagen");
  });
}

