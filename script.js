// ====== MelonTec Cloud JS Optimiert ======
const MTCloud = (() => {
  let currentUser = null;
  const usersKey = 'mtcloud_users';
  const authModal = document.getElementById('authModal');
  const modalTitle = document.getElementById('modalTitle');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const authSubmit = document.getElementById('authSubmit');
  const settingsBtn = document.getElementById('settingsBtn');
  const twoFAInfo = document.getElementById('twoFAInfo');
  const cloudContent = document.querySelector('.cloud-content');
  const tabContent = document.getElementById('tabContent');
  const tabs = document.querySelectorAll('.tabs button');

  // ===== Helper =====
  const toast = msg => {
    const t = document.createElement('div');
    t.className='toast'; t.innerText=msg;
    document.body.appendChild(t);
    setTimeout(()=>document.body.removeChild(t),3000);
  };

  const saveUser = user => {
    let all = JSON.parse(localStorage.getItem(usersKey)) || {};
    all[user.username] = user;
    localStorage.setItem(usersKey, JSON.stringify(all));
  };

  const loadUser = username => {
    const all = JSON.parse(localStorage.getItem(usersKey)) || {};
    return all[username] || null;
  };

  // ===== Auth Flow =====
  const openAuth = (mode='login') => {
    modalTitle.innerText = mode==='login'?'Login':'Account erstellen';
    authSubmit.innerText = mode==='login'?'Einloggen':'Registrieren';
    twoFAInfo.style.display='none';
    authModal.style.display='flex';
    authSubmit.onclick = () => handleAuth(mode);
  };

  const handleAuth = mode => {
    const user = usernameInput.value.trim();
    const pass = passwordInput.value.trim();
    if(!user||!pass){toast('Bitte alle Felder ausfüllen'); return;}
    let uObj = loadUser(user);

    if(mode==='login'){
      if(!uObj || uObj.password!==pass){
        toast('Falscher Benutzername oder Passwort'); return;
      }
    } else {
      if(uObj){toast('Benutzer existiert bereits'); return;}
      uObj = {username:user,password:pass,files:[],twoFA:false};
      saveUser(uObj);
      toast('Account erstellt!');
    }

    currentUser = uObj;
    authModal.style.display='none';
    cloudContent.style.display='flex';
    settingsBtn.style.display='inline-block';
    toast(`Willkommen, ${user}!`);
    usernameInput.value=''; passwordInput.value='';
    loadTab('photos');
    render2FA();
  };

  // ===== Settings & 2FA =====
  settingsBtn.addEventListener('click', ()=>{
    if(!currentUser) return;
    const enable2FA = confirm('2FA aktivieren? (Demo)');
    currentUser.twoFA = enable2FA;
    saveUser(currentUser);
    render2FA();
    toast(`2FA ${enable2FA?'aktiviert':'deaktiviert'}`);
  });

  const render2FA = () => {
    twoFAInfo.style.display = currentUser?.twoFA ? 'block' : 'none';
  };

  // ===== Tabs =====
  tabs.forEach(tab => tab.addEventListener('click', ()=>{
    tabs.forEach(t=>t.classList.remove('active'));
    tab.classList.add('active');
    loadTab(tab.dataset.tab);
  }));

  const loadTab = tab => {
    if(!currentUser) return;
    if(tab==='photos'){
      tabContent.innerHTML='<p>Hier werden deine Fotos angezeigt.</p>';
    } else if(tab==='notes'){
      tabContent.innerHTML='<p>Hier kannst du Notizen erstellen.</p>';
    } else if(tab==='melmail'){
      tabContent.innerHTML='<p>Hier wird deine MelMail angezeigt.</p>';
    } else if(tab==='meldat'){
      tabContent.innerHTML=`<div class="upload-area" id="uploadArea">Dateien hierhin ziehen oder klicken</div>
      <div class="file-list" id="fileList"></div>`;
      initFileUpload();
    }
  };

  // ===== File Upload =====
  const initFileUpload = () => {
    const uploadArea = document.getElementById('uploadArea');
    const fileList = document.getElementById('fileList');
    const userData = currentUser;

    const renderFiles = () => {
      fileList.innerHTML='';
      userData.files.forEach((f,i)=>{
        const div = document.createElement('div'); div.className='file-item';
        div.innerHTML=`<span>${f.name}</span>
          <div>
            <button onclick="MTCloud.downloadFile(${i})">Download</button>
            <button onclick="MTCloud.deleteFile(${i})">Löschen</button>
          </div>`;
        fileList.appendChild(div);
      });
    };

    const handleFiles = files => {
      Array.from(files).forEach(file=>{
        const reader = new FileReader();
        reader.onload = e=>{
          userData.files.push({name:file.name,data:e.target.result,type:file.type});
          renderFiles();
          saveUser(userData);
          toast(`Datei "${file.name}" hochgeladen!`);
        };
        reader.readAsDataURL(file);
      });
    };

    uploadArea.addEventListener('click',()=>{ 
      const input = document.createElement('input'); input.type='file'; input.multiple=true;
      input.onchange=e=>handleFiles(e.target.files); input.click();
    });
    uploadArea.addEventListener('dragover',e=>{e.preventDefault(); uploadArea.style.background='rgba(95,224,200,0.2)';});
    uploadArea.addEventListener('dragleave',e=>{uploadArea.style.background='none';});
    uploadArea.addEventListener('drop',e=>{e.preventDefault(); uploadArea.style.background='none'; handleFiles(e.dataTransfer.files);});

    renderFiles();
  };

  // ===== File Actions Global =====
  const downloadFile = i => {
    const f = currentUser.files[i];
    const a = document.createElement('a');
    a.href=f.data; a.download=f.name; a.click();
  };

  const deleteFile = i => {
    if(!confirm('Datei wirklich löschen?')) return;
    currentUser.files.splice(i,1);
    saveUser(currentUser);
    loadTab('meldat');
    toast('Datei gelöscht');
  };

  // ===== Expose Global =====
  return {openAuth, downloadFile, deleteFile};
})();

// ===== Init Buttons =====
document.getElementById('loginBtn').onclick = ()=>MTCloud.openAuth('login');
document.getElementById('registerBtn').onclick = ()=>MTCloud.openAuth('register');
