window.onload = function() {
    const token = localStorage.getItem("token");
    
    if (!token) {
        document.querySelector('.account-btn button').innerText = "Login";
    } else {
        document.querySelector('.account-btn button').innerText = "Account";
    }
};
