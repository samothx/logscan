+++
name = "wordpress"
description = "Example of a focused skill: weekly look at WordPress admin/API traffic only (disabled)"
enabled = false
every_days = 7
max_input_chars = 50000

[[input]]
dataset = "nginx.filtered"
trusted = false
path = '^/(?:wp-admin|wp-login\.php|xmlrpc\.php|wp-json|wp-content/(?:plugins|uploads))'
limit = 300

[[input]]
dataset = "nginx.ip_profiles"
path = '^/(?:wp-admin|wp-login\.php|xmlrpc\.php|wp-json)'
limit = 25
+++
Focus on the WordPress sites (to limit it to some hosts, add `host = ["example.org", …]` to the inputs). Look for signs of a compromised site: successful logins from IPs that
also brute-forced, admin-ajax/wp-json calls that change content or users, requests to PHP files in
`wp-content/uploads`, newly appearing plugin paths, and REST API user enumeration that succeeded.
