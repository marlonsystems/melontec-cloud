async function uploadVideo(input) {
  const file = input.files[0];
  const user = (await supabase.auth.getUser()).data.user;

  const path = `${user.id}/${Date.now()}-${file.name}`;

  await supabase.storage.from('videos').upload(path, file);

  const { data } = supabase.storage.from('videos').getPublicUrl(path);

  await supabase.from('media').insert({
    user_id: user.id,
    type: 'video',
    url: data.publicUrl
  });

  loadVideos();
}

async function loadVideos() {
  const { data } = await supabase.from('media')
    .select('*')
    .eq('type','video');

  document.getElementById('videos').innerHTML =
    data.map(v => `<video src="${v.url}" controls width="300"></video>`).join('');
}

loadVideos();
