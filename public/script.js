/* script.js - shared header/nav manager with logo */
(function () {
  function onReady(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  onReady(() => {
    const nav = document.querySelector('nav');
    if (!nav) return;
    
    // Update logo to include image
    const logoDiv = nav.querySelector('.logo');
    if (logoDiv && !logoDiv.querySelector('.logo-img')) {
      logoDiv.innerHTML = `
        <img src="/logo.png" alt="Notion IQ Logo" class="logo-img">
        <span class="logo-text">Notion IQ</span>
      `;
    }
    
    let ul = nav.querySelector('ul');
    if (!ul) { ul = document.createElement('ul'); nav.appendChild(ul); }

    function getStorage(k) { try{return sessionStorage.getItem(k)}catch(e){return null} }
    function setStorage(k,v) { try{sessionStorage.setItem(k,v)}catch(e){} }
    function rmStorage(k) { try{sessionStorage.removeItem(k)}catch(e){} }

    function createLink(href, text, active) {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = href; a.textContent = text;
      if(active) a.classList.add('active');
      li.appendChild(a);
      return li;
    }

    function renderNav(loggedIn, user) {
      ul.innerHTML = '';
      const path = window.location.pathname.replace(/^\/+/, '');

      // Home
      ul.appendChild(createLink('/index.html', 'Home', path === '' || path === 'index.html'));
      
      // About
      ul.appendChild(createLink('/about.html', 'About', path === 'about.html'));

      if (loggedIn) {
        // Notion (Quick Analysis)
        ul.appendChild(createLink('/Notion.html', 'Quick Notes', path === 'Notion.html'));

        // Detailed Analysis
        ul.appendChild(createLink('/detailed-analysis.html', 'Detailed Analysis', path === 'detailed-analysis.html'));

        // Important Points (Dynamic Link - if exists)
        const lastPointsUrl = getStorage('notioniq_last_points_url');
        if (lastPointsUrl) {
          const isPointsPage = path.includes('important/');
          ul.appendChild(createLink(lastPointsUrl, 'Study Guide', isPointsPage));
        }

        // Quiz (Only if questions exist)
        const hasQuiz = getStorage('aiQuizQuestions');
        if (hasQuiz) {
          ul.appendChild(createLink('/take-quiz.html', 'Take Quiz', path === 'take-quiz.html'));
        }

        // Sign Out
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.textContent = user ? `Sign Out (${user})` : 'Sign Out';
        a.href = '#';
        a.onclick = async (e) => {
          e.preventDefault();
          await fetch('/api/signout', { method:'POST' }).catch(()=>{});
          rmStorage('notioniq_logged_in');
          rmStorage('notioniq_user');
          rmStorage('notioniq_last_points_url');
          rmStorage('aiQuizQuestions');
          window.location.href = '/index.html';
        };
        li.appendChild(a);
        ul.appendChild(li);
      } else {
        ul.appendChild(createLink('/signin.html', 'Sign In', path === 'signin.html'));
      }
    }

    // Initialize
    const loggedIn = getStorage('notioniq_logged_in') === '1';
    const user = getStorage('notioniq_user');
    
    if (loggedIn) {
      renderNav(true, user);
    } else {
      fetch('/api/me').then(r=>r.json()).then(d=>{
        if(d.authenticated){
          setStorage('notioniq_logged_in','1');
          setStorage('notioniq_user', d.user.name);
          renderNav(true, d.user.name);
        } else {
          renderNav(false);
        }
      }).catch(()=>renderNav(false));
    }

    // Expose updateNav function globally
    window._NotionIQAuth = { 
      updateNav: () => renderNav(true, getStorage('notioniq_user')),
      setLoggedInFlag: (username) => {
        setStorage('notioniq_logged_in', '1');
        if (username) setStorage('notioniq_user', username);
        renderNav(true, username);
      }
    };
  });
})();