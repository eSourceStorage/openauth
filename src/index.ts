<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>returnedmath's basement</title>
  <style>
    :root {
      --blue-1: #3d5afe;
      --blue-2: #536dfe;
      --blue-3: #304ffe;
      --red: #f50057;
      --white: #ffffff;
      --dark: #0a0a0c;
      --glass: rgba(255, 255, 255, 0.03);
      --glass-stroke: rgba(255, 255, 255, 0.05);
    }

    body {
      background: var(--dark);
      margin: 0;
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
      color: var(--white);
      line-height: 1.5;
    }

    .content {
      position: relative;
      width: 90vw;
      max-width: 1400px;
      margin: 0 auto;
      padding: 8rem 0;
    }

    .background {
      position: fixed;
      inset: 0;
      z-index: -1;
      overflow: hidden;
    }

    .ball {
      position: absolute;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.4;
    }

    .ball-1 {
      width: 300px;
      height: 300px;
      background: linear-gradient(135deg, var(--blue-1) 0%, var(--blue-3) 50%, var(--blue-2) 100%);
      top: 10%;
      left: -50px;
      animation: float1 25s infinite;
    }

    .ball-2 {
      width: 200px;
      height: 200px;
      background: linear-gradient(135deg, var(--white) 0%, var(--blue-2) 100%);
      bottom: 10%;
      right: -50px;
      animation: float2 18s infinite;
    }

    .ball-3 {
      width: 250px;
      height: 250px;
      background: linear-gradient(135deg, var(--blue-3) 0%, var(--red) 100%);
      top: 50%;
      left: 20%;
      animation: float3 30s infinite;
    }

    @keyframes float1 {
      0%, 100% { transform: translate(0, 0) rotate(0deg); }
      50% { transform: translate(100px, 100px) rotate(180deg); }
    }

    @keyframes float2 {
      0%, 100% { transform: translate(0, 0) rotate(0deg); }
      50% { transform: translate(-100px, -50px) rotate(-180deg); }
    }

    @keyframes float3 {
      0% { transform: translate(-50%, -50%) rotate(0deg); }
      100% { transform: translate(-50%, -50%) rotate(360deg) translate(150px) rotate(-360deg); }
    }

    .navbar {
      position: fixed;
      top: 2rem;
      left: 5vw;
      right: 5vw;
      background: var(--glass);
      backdrop-filter: blur(20px);
      border: 1px solid var(--glass-stroke);
      border-radius: 1rem;
      padding: 1rem 2rem;
      z-index: 100;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .navbar-menu {
      display: flex;
      gap: 2rem;
    }

    .navbar-menu a {
      text-decoration: none;
      color: var(--white);
      opacity: 0.7;
      transition: all 0.3s ease;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      background: var(--glass);
      border: 1px solid var(--glass-stroke);
      font-weight: 500;
    }

    .navbar-menu a:hover {
      opacity: 1;
      background: rgba(255, 255, 255, 0.05);
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.1);
    }

    .navbar-menu a.active {
      opacity: 1;
      background: linear-gradient(135deg, var(--blue-1), var(--blue-3));
      border: none;
    }

    .section {
      margin-bottom: 8rem;
      max-width: 800px;
      margin-inline: auto;
    }

    .section-header {
      margin-bottom: 3rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .view-progress {
      color: var(--white);
      opacity: 0.7;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      transition: opacity 0.3s ease;
    }

    .view-progress:hover {
      opacity: 1;
    }

    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 2rem;
    }

    .card {
      background: rgba(255, 255, 255, 0.02);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 20px;
      padding: 2rem;
      transition: all 0.4s cubic-bezier(0.2, 0.8, 0.2, 1);
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .card:hover {
      transform: translateY(-4px);
      border-color: var(--glass-stroke-hover);
      background: var(--glass-hover);
    }

    .card-icon {
      width: 48px;
      height: 48px;
      background: linear-gradient(135deg, var(--blue-1), var(--blue-3));
      border-radius: 12px;
      display: grid;
      place-items: center;
      color: var(--white);
    }

    .card-content {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .card-content h3 {
      font-size: 1.25rem;
      margin-bottom: 0.5rem;
    }

    .card-content p {
      opacity: 0.7;
      margin-bottom: 1.5rem;
    }

    .btn {
      background: var(--glass);
      color: var(--color-white);
      border: 1px solid var(--glass-stroke);
      padding: 0.75rem 1.5rem;
      border-radius: 0.75rem;
      font-weight: 500;
      transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1);
      margin-top: auto;
      align-self: flex-start;
    }

    .btn:hover {
      border-color: var(--glass-stroke-hover);
      background: var(--bg-gradient);
      transform: translateY(-2px);
    }

    footer {
      background: var(--glass);
      backdrop-filter: blur(20px);
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding: 2rem;
      text-align: center;
    }

    .user-menu {
      position: relative;
    }

    .user-icon {
      width: 35px;
      height: 35px;
      border-radius: 50%;
      background: linear-gradient(135deg, var(--blue-1), var(--blue-3));
      display: grid;
      place-items: center;
      color: var(--white);
      cursor: pointer;
      transition: transform 0.2s;
    }

    .user-icon:hover {
      transform: scale(1.1);
    }

    .user-dropdown {
      position: absolute;
      top: 100%;
      right: 0;
      margin-top: 0.5rem;
      background: var(--glass);
      backdrop-filter: blur(20px);
      border: 1px solid var(--glass-stroke);
      border-radius: 0.75rem;
      padding: 0.5rem;
      display: none;
    }

    .user-dropdown.active {
      display: block;
    }

    .user-dropdown a {
      display: block;
      padding: 0.5rem 1rem;
      color: var(--white);
      text-decoration: none;
      border-radius: 0.5rem;
    }

    .user-dropdown a:hover {
      background: rgba(255, 255, 255, 0.05);
    }

    @media (max-width: 640px) {
      .card {
        gap: 1rem;
      }

      .btn {
        width: 100%;
        text-align: center;
      }
    }
</style>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <script type="module">
    import { authConfig } from './auth.js';

    // Auth state management
    const AUTH_STATE = {
      isLoggedIn: false,
      user: null,
      authDomain: 'https://auth.returnedmath.xyz'
    };

    // Updated auth initialization with proper domains
    window.initAuth = async () => {
      try {
        const url = new URL(`${AUTH_STATE.authDomain}/authorize`);
        url.searchParams.set("redirect_uri", "https://returnedmath.xyz/auth-callback");
        url.searchParams.set("client_id", authConfig.clientId);
        url.searchParams.set("response_type", "code");
        window.location.href = url.toString();
      } catch (err) {
        console.error("Auth error:", err);
      }
    };

    // Updated callback handling
    if (window.location.pathname === '/auth-callback') {
      const params = new URLSearchParams(window.location.search);
      
      // Check for errors first
      if (params.has('error')) {
        console.error("Auth error:", params.get('error_description'));
        alert("Authentication failed: " + params.get('error_description'));
        window.location.href = '/';
        throw new Error(params.get('error_description'));
      }

      const code = params.get('code');
      if (code) {
        try {
          const response = await fetch(`${AUTH_STATE.authDomain}/callback`, {
            method: 'POST',
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
              'Origin': 'https://returnedmath.xyz'
            },
            body: JSON.stringify({ code })
          });

          if (!response.ok) {
            throw new Error('Auth request failed');
          }

          const data = await response.json();
          if (data.message === 'success') {
            AUTH_STATE.isLoggedIn = true;
            AUTH_STATE.user = data.user;
            handleLoginSuccess();
            window.location.href = data.redirect || '/';
          } else if (data.message === 'error') {
            throw new Error(data.description || 'Authentication failed');
          }
        } catch (err) {
          console.error("Auth callback error:", err);
          alert("Authentication failed: " + err.message);
          window.location.href = '/';
        }
      }
    }
  </script>
</head>
<body>
  <div class="background">
    <div class="ball ball-1"></div>
    <div class="ball ball-2"></div>
    <div class="ball ball-3"></div>
  </div>
  <div class="content">
    <nav class="navbar">
      <h1>returnedmath's basement</h1>
      <div class="navbar-menu">
        <a href="#" class="active">Home</a>
        <a href="/tracker">Progress</a>
        <a href="/shitpost">Shitpost</a>
        <a href="mailto:returnedmath@awareroblox.xyz">Contact</a>
        <div id="auth-container">
          <button id="loginBtn" class="btn" onclick="initAuth()">Login</button>
          <div id="userMenu" class="user-menu" style="display: none">
            <div class="user-icon">
              <i class="fas fa-user"></i>
            </div>
            <div class="user-dropdown">
              <a href="/profile">Profile</a>
              <a href="#" onclick="logout()">Logout</a>
            </div>
          </div>
        </div>
      </div>
    </nav>

    <main>
      <section class="section">
        <div class="section-header">
          <h2>thingies i made</h2>
          <a href="/tracker" class="view-progress">
            View Progress
            <i class="fas fa-arrow-right"></i>
          </a>
        </div>

        <div class="cards">
          <div class="card">
            <div class="card-icon"><i class="fas fa-globe"></i></div>
            <div class="card-content">
              <h3>web config</h3>
              <p>web config menu</p>
              <button class="btn" onclick="window.location.href='/products/web-config'">Download</button>
            </div>
          </div>
          <div class="card">
            <div class="card-icon"><i class="fas fa-tablet"></i></div>
            <div class="card-content">
              <h3>Tablet Ordering System</h3>
              <p>very gud addon for ezpos cafepos, download now free i said!!!!!11</p>
              <button class="btn" onclick="window.location.href='/products/tablet'">Download</button>
            </div>
          </div>
        </div>
      </section>

      <section class="section">
        <div class="section-header">
          <h2>random stuff</h2>
        </div>

        <div class="cards">
          <div class="card">
            <div class="card-icon"><i class="fas fa-e"></i></div>
            <div class="card-content">
              <h3>Best POS systemo for boblox</h3>
              <p>I SAID BUY THEIR CAFEPOS NOW!!! (and make sure to use tablet ordering system)</p>
            </div>
            <button class="btn" onclick="window.location.href='/selection'">Visit</button>
          </div>

          <div class="card">
            <div class="card-icon"><i class="fas fa-store"></i></div>
            <div class="card-content">
              <h3>Best Retail stuffs for boblox (like scos)</h3>
              <p>hmmmm?? axon.whitehill.group??!?!?!?!</p>
            </div>
            <button class="btn" onclick="window.location.href='http://axon.whitehill.group'">Visit</button>
          </div>

          <div class="card">
            <div class="card-icon"><i class="fas fa-lightbulb"></i></div>
            <div class="card-content">
              <h3>Best light stuffs for boblox</h3>
              <p>native!11!1 (not fisch related idiidiot)</p>
            </div>
            <button class="btn" onclick="window.location.href='http://discord.gg/native'">Visit</button>
          </div>
        </div>
      </section>
    </main>

    <footer>
      <p>returnedmath is a cutie returnedmath is a cutie returnedmath is a cutie returnedmath is a cutie returnedmath is a cutie</p>
    </footer>
  </div>

  <script>
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
          behavior: 'smooth'
        });
      });
    });

    // Toggle user menu on click
    const userIcon = document.querySelector('.user-icon');
    const userDropdown = document.querySelector('.user-dropdown');

    userIcon?.addEventListener('click', () => {
      userDropdown?.classList.toggle('active');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      const target = e.target;
      if (!userIcon?.contains(target)) {
        userDropdown?.classList.remove('active');
      }
    });

    // Check auth state and show correct menu
    function updateAuthUI(isLoggedIn) {
      const loginBtn = document.getElementById('loginBtn');
      const userMenu = document.getElementById('userMenu');
      
      if (!loginBtn || !userMenu) return;

      loginBtn.style.display = isLoggedIn ? 'none' : 'block';
      userMenu.style.display = isLoggedIn ? 'block' : 'none';
    }

    // Call this after successful login
    function handleLoginSuccess() {
      updateAuthUI(true);
    }

    // Fixed logout handler
    async function logout() {
      try {
        await fetch(`${AUTH_STATE.authDomain}/logout`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Origin': 'https://returnedmath.xyz'
          }
        });
        AUTH_STATE.isLoggedIn = false;
        AUTH_STATE.user = null;
        updateAuthUI(false);
      } catch (err) {
        console.error("Logout error:", err);
      }
    }

    // Check initial auth state
    const isLoggedIn = document.cookie.includes('user_id=');
    updateAuthUI(isLoggedIn);
  </script>
</body>
</html>

<script src="/redirect.js"></script>
