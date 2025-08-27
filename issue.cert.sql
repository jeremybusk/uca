SELECT issue_certificate(
    '2f7be92d-f285-4e11-a70f-f4dd639c0ec3',
    'www.example.com',
    ARRAY['example.com', 'api.example.com'],
    'Example Corp',
    'IT',
    'US',
    'CA',
    'San Francisco',
    'admin@example.com',
    'server',
    'rsa',
    2048,
    'sha256',
    365,
    ARRAY['digitalSignature', 'keyEncipherment'],
    ARRAY['serverAuth'],
    NULL, -- Template ID
    NULL, -- Certificate PEM
    NULL, -- Private key PEM
    'my_master_password',
    'admin'
);
