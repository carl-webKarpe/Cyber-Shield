<?php
/** Prints a random value for agent_enrollment_key in config.local.php. */
echo bin2hex(random_bytes(24)), PHP_EOL;
