SELECT create_certificate_authority(
    'My Root CA',
    'My Root CA',
    'My Organization',
    'IT Department',
    'US',
    'CA',
    'San Francisco',
    'ca@myorg.com',
    'root_ca',
    NULL, -- No parent for root CA
    'rsa',
    4096,
    'sha256',
    7300, -- 20 years
    ARRAY['keyCertSign', 'cRLSign'],
    NULL,
    NULL, -- No path length constraint for root
    NULL, -- Certificate PEM (would be generated externally)
    NULL, -- Private key PEM (would be generated externally)
    'my_master_password',
    'admin'
);
