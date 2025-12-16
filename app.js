const token = localStorage.getItem("token");
const accountBtn = document.getElementById("accountBtn");

if (token) {
  accountBtn.textContent = "Profil";
} else {
  accountBtn.textContent = "Login";
  accountBtn.onclick = () => location.href = "login.html";
}
