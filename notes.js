<script>
async function loadNotes() {
  const user = (await supabase.auth.getUser()).data.user;

  const { data } = await supabase
    .from("notes")
    .select("*")
    .eq("user_id", user.id);

  notes.innerHTML = data.map(n => `<p>${n.content}</p>`).join("");
}

async function addNote(text) {
  const user = (await supabase.auth.getUser()).data.user;

  await supabase.from("notes").insert({
    user_id: user.id,
    content: text
  });

  loadNotes();
}
</script>
