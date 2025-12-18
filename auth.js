<script>
async function login() {
  const { error } = await supabase.auth.signInWithPassword({
    email: email.value,
    password: password.value
  });

  if (error) alert(error.message);
  else location.href = "index.html";
}

async function register() {
  const { error } = await supabase.auth.signUp({
    email: email.value,
    password: password.value
  });

  if (error) alert(error.message);
  else alert("Account erstellt – bitte einloggen");
}

async function logout() {
  await supabase.auth.signOut();
  location.href = "login.html";
}
</script>
