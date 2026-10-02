+++
name = "wordpress"
description = "Example of a focused skill: weekly look at the WordPress sites only (disabled)"
enabled = false
every_days = 7
max_input_chars = 50000

[[input]]
dataset = "nginx.filtered"
host = ["etnur.net", "www.etnur.net", "gaylyn.etnur.net", "yogamitselina.de", "www.yogamitselina.de"]
trusted = false
path = '^/(?:wp-admin|wp-login\.php|xmlrpc\.php|wp-json|wp-content/(?:plugins|uploads))'
limit = 300

[[input]]
dataset = "nginx.ip_profiles"
host = ["etnur.net", "www.etnur.net", "gaylyn.etnur.net", "yogamitselina.de", "www.yogamitselina.de"]
limit = 25
+++
Focus on the WordPress sites. Look for signs of a compromised site: successful logins from IPs that
also brute-forced, admin-ajax/wp-json calls that change content or users, requests to PHP files in
`wp-content/uploads`, newly appearing plugin paths, and REST API user enumeration that succeeded.
