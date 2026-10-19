<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
	'httponly' => true,
	'samesite' => 'Lax',
	'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

if (empty($_SESSION['user']['id']) || time() - (int) ($_SESSION['last_activity'] ?? 0) > 28800) {
	$_SESSION = [];
	session_destroy();
	header('Location: login.php');
	exit;
}

$_SESSION['last_activity'] = time();
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="theme-color" content="#07111e">
	<title>My Profile — Cyber Shield</title>
	<script src="js/auth.js"></script>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&amp;family=Inter:wght@400;500;600;700&amp;family=IBM+Plex+Mono:wght@500&amp;display=swap" rel="stylesheet">
	<link rel="stylesheet" href="css/style.css">
</head>
<body>
	<main class="main profile-main">
		<div class="view-head">
			<div>
				<h1>My Profile</h1>
				<p class="subhead">Your Cyber Shield account details.</p>
			</div>
				<div class="head-actions">
					<button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch to light mode" title="Switch to light mode">
						<svg class="theme-icon theme-icon--sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/></svg>
						<svg class="theme-icon theme-icon--moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.8 14.2A8.8 8.8 0 0 1 9.8 3.2 8.8 8.8 0 1 0 20.8 14.2z"/></svg>
						<span data-theme-label>Light mode</span>
					</button>
					<a class="btn btn-outline" href="index.php">Back to dashboard</a>
				</div>
		</div>

			<section class="panel profile-panel" aria-labelledby="profileHeading" data-user-profile>
			<div class="panel-head">
				<h2 id="profileHeading">Account details</h2>
			</div>
			<div class="profile-identity">
					<span class="account-avatar" id="profileAvatar" aria-hidden="true">CS</span>
				<div>
						<h2 id="profileDisplayName">Loading profile…</h2>
						<p id="profileDisplayEmail">Loading account details…</p>
				</div>
			</div>
			<div class="profile-fields">
					<div class="about-row"><span>Full name</span><span id="profileName">Loading…</span></div>
					<div class="about-row"><span>Email</span><span id="profileEmail">Loading…</span></div>
					<div class="about-row"><span>Role</span><span id="profileRole">Loading…</span></div>
					<div class="about-row"><span>Member since</span><span id="profileCreatedAt">Loading…</span></div>
					<div class="about-row"><span>Last sign-in</span><span id="profileLastLogin">Loading…</span></div>
			</div>
				<p class="profile-error" id="profileError" role="status" aria-live="polite" hidden></p>
		</section>
	</main>
		<script src="js/user.js"></script>
</body>
</html>
