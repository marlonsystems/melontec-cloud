async function login() {
  const email = email.value;
  const password = password.value;

  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (!error) location.href = "index.html";
}

async function register() {
  const { error } = await supabase.auth.signUp({
    email: email.value,
    password: password.value
  });
  if (!error) location.href = "index.html";
}

async function logout() {
  await supabase.auth.signOut();
  location.href = "login.html";
}
