<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';
cs_start_session();
if (cs_current_user($pdo) !== null) {
	header('Location: index.php');
	exit;
}
$allowRegistration = (bool) cs_config('allow_registration');
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="theme-color" content="#07111e">
	<meta name="csrf-token" content="<?php echo cs_e(cs_csrf_token()); ?>">
	<title>Sign in — Cyber-Shield</title>
	<script src="js/auth.js"></script>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="css/style.css">
</head>
<body class="login-page">
	<main class="login-shell">
		<section class="login-aside" aria-label="Cyber-Shield security overview">
			<a class="login-brand" href="login.php" aria-label="Cyber-Shield sign in">
				<svg class="brand-icon" viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M20 3 5 9v10c0 9.94 6.4 18.9 15 21 8.6-2.1 15-11.06 15-21V9L20 3z" fill="url(#loginShield)"/><path d="m14 20.5 4 4 8-8.5" stroke="#04141f" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="loginShield" x1="5" y1="3" x2="35" y2="40"><stop stop-color="#39c6ff"/><stop offset="1" stop-color="#2e6fe8"/></linearGradient></defs></svg>
				<span><strong>Cyber-Shield</strong><small>LAB SECURITY MONITORING</small></span>
			</a>
			<div class="login-aside-content">
				<span class="eyebrow">SECURITY OPERATIONS</span>
				<h1>Know what is<br>happening on<br>your network.</h1>
				<p>One workspace for scan activity, endpoint health, and incident response.</p>
			</div>
			<div class="login-visual" aria-hidden="true">
				<div class="orbit orbit--outer"></div><div class="orbit orbit--inner"></div>
				<span class="orbit-node orbit-node--one"></span><span class="orbit-node orbit-node--two"></span><span class="orbit-node orbit-node--three"></span>
				<div class="orbit-core"><svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5.3 3.4 9.2 8 11 4.6-1.8 8-5.7 8-11V5l-8-3z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg></div>
				<span class="visual-label visual-label--one">LAB AGENTS <b>LAN</b></span><span class="visual-label visual-label--two">VIRUSTOTAL <b>LIVE</b></span>
			</div>
			<div class="login-aside-foot"><span class="status-dot status-dot--safe"></span> Cyber-Shield monitoring server <span>v<?php echo cs_e(CS_VERSION); ?></span></div>
		</section>

		<section class="login-main">
			<div class="login-top-controls">
				<button class="theme-toggle theme-toggle--login" type="button" data-theme-toggle aria-label="Switch to light mode" title="Switch to light mode">
					<svg class="theme-icon theme-icon--sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/></svg>
					<svg class="theme-icon theme-icon--moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.8 14.2A8.8 8.8 0 0 1 9.8 3.2 8.8 8.8 0 1 0 20.8 14.2z"/></svg>
					<span data-theme-label>Light mode</span>
				</button>
			</div>
			<div class="login-form-wrap">
				<div class="login-brand-mark" aria-hidden="true">
					<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
						<path d="M20 2.5 6.5 9.5v9.7c0 9.8 6 18.6 13.5 21.4 7.5-2.8 13.5-11.6 13.5-21.4v-9.7L20 2.5Z" fill="url(#visionGuardGrad)"/>
						<path d="M20 2.5 6.5 9.5v9.7c0 9.8 6 18.6 13.5 21.4 7.5-2.8 13.5-11.6 13.5-21.4v-9.7L20 2.5Z" stroke="#7DD9FF" stroke-opacity="0.45"/>
						<path d="M14 20.5 18 24.5l8-9" stroke="#051A29" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
						<defs>
							<linearGradient id="visionGuardGrad" x1="6.5" y1="2.5" x2="33.5" y2="40" gradientUnits="userSpaceOnUse">
								<stop stop-color="#31D5FF"/>
								<stop offset="1" stop-color="#2C75FF"/>
							</linearGradient>
						</defs>
					</svg>
				</div>
				<h2>Welcome back</h2>
				<p class="login-intro">Sign in to your Cyber-Shield workspace.</p>
				<form id="loginForm" class="login-form" novalidate data-allow-registration="<?php echo $allowRegistration ? '1' : '0'; ?>">
					<label for="loginName" data-register-field hidden>Full name</label>
					<input id="loginName" name="name" type="text" placeholder="Your name" autocomplete="name" maxlength="100" data-register-field hidden>
					<label for="loginEmail">Email</label>
					<div class="field-with-icon">
						<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 21a8 8 0 1 0-16 0m8-9a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
						<input id="loginEmail" name="email" type="email" placeholder="you@lab.local" autocomplete="username" required>
					</div>
					<div class="password-label"><label for="loginPassword">Password</label><span id="passwordHint"></span></div>
					<div class="field-with-icon password-field">
						<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10V8a5 5 0 1 1 10 0v2M6 10h12v10H6z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
						<input id="loginPassword" name="password" type="password" placeholder="Password" autocomplete="current-password" required>
						<button id="togglePassword" type="button" aria-label="Show password" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg></button>
					</div>
					<div class="meta-row">
						<label class="remember-row"><input type="checkbox" name="remember" checked> Remember me</label>
						<span class="text-link" title="Ask your Cyber-Shield Super Admin to reset your password">Forgot password? Ask your Super Admin.</span>
					</div>
					<p id="loginMessage" class="login-message" role="status" aria-live="polite" hidden></p>
					<button class="btn btn-primary login-submit" type="submit"><span>Sign in</span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg></button>
				</form>
				<?php if ($allowRegistration): ?>
				<p class="login-switch"><span id="switchPrompt">New to Cyber-Shield?</span> <button id="switchAuthMode" type="button">Create an account</button></p>
				<?php else: ?>
				<p class="login-switch">Accounts are created by your Cyber-Shield Super Admin.</p>
				<?php endif; ?>
				<div class="login-divider"><span>SECURE ACCESS</span></div>
				<a class="scan-quick" id="scanQuickUrl" href="index.php?view=url"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5 4.5 9v6c0 5.6 3.4 10.1 7.5 11.5 4.1-1.4 7.5-5.9 7.5-11.5V9L12 2.5Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m9.2 12.8 1.5 1.5 4.1-4.3" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>Scan a URL with VirusTotal</a>
				<p class="security-note"><span>🔒</span> Authorized lab personnel only. Sign-ins are recorded in the Cyber-Shield audit log.</p>
			</div>
		</section>
	</main>
	<script src="js/login.js"></script>
</body>
</html>
