-- Insert default encryption configuration
INSERT INTO encryption_config (config_name, cipher_type, iterations)
VALUES ('default_aes256', 'aes256-cbc', 100000);

-- Insert some default certificate templates
INSERT INTO certificate_templates (
    template_name, cert_type, key_algorithm, key_size, hash_algorithm,
    validity_period_days, key_usage, extended_key_usage
) VALUES
('server_cert', 'server', 'rsa', 2048, 'sha256', 365,
 ARRAY['digitalSignature', 'keyEncipherment'], ARRAY['serverAuth']),
('client_cert', 'client', 'rsa', 2048, 'sha256', 365,
 ARRAY['digitalSignature'], ARRAY['clientAuth']),
('code_signing_cert', 'code_signing', 'rsa', 2048, 'sha256', 1095,
 ARRAY['digitalSignature'], ARRAY['codeSigning']);
