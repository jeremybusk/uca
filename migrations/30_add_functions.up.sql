--
-- Name: create_certificate_authority(character varying, character varying, character varying, character varying, character, character varying, character varying, character varying, public.certificate_type, uuid, public.key_algorithm, integer, public.hash_algorithm, integer, text[], text[], integer, text, text, text, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.create_certificate_authority(p_ca_name character varying, p_common_name character varying, p_organization character varying DEFAULT NULL::character varying, p_organizational_unit character varying DEFAULT NULL::character varying, p_country character DEFAULT NULL::bpchar, p_state_province character varying DEFAULT NULL::character varying, p_locality character varying DEFAULT NULL::character varying, p_email character varying DEFAULT NULL::character varying, p_cert_type public.certificate_type DEFAULT 'intermediate_ca'::public.certificate_type, p_parent_ca_id uuid DEFAULT NULL::uuid, p_key_algorithm public.key_algorithm DEFAULT 'rsa'::public.key_algorithm, p_key_size integer DEFAULT 2048, p_hash_algorithm public.hash_algorithm DEFAULT 'sha256'::public.hash_algorithm, p_validity_days integer DEFAULT 3650, p_key_usage text[] DEFAULT ARRAY['keyCertSign'::text, 'cRLSign'::text], p_extended_key_usage text[] DEFAULT NULL::text[], p_path_length_constraint integer DEFAULT NULL::integer, p_certificate_pem text DEFAULT NULL::text, p_private_key_pem text DEFAULT NULL::text, p_master_password text DEFAULT NULL::text, p_created_by character varying DEFAULT NULL::character varying) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    new_ca_id UUID;
    serial_num NUMERIC(39,0);
    not_before_date TIMESTAMPTZ;
    not_after_date TIMESTAMPTZ;
    is_root_ca BOOLEAN;
    encrypted_key_data BYTEA;
    key_salt_data BYTEA;
    encryption_config_id_val UUID;
BEGIN
    is_root_ca := (p_parent_ca_id IS NULL);

    serial_num := generate_serial_number();

    not_before_date := NOW();
    not_after_date  := NOW() + (p_validity_days || ' days')::INTERVAL;

    IF p_certificate_pem IS NOT NULL AND p_private_key_pem IS NOT NULL THEN
        -- Encrypt provided private key, will also return config_used
        SELECT encrypted_key, salt, config_used 
          INTO encrypted_key_data, key_salt_data, encryption_config_id_val
        FROM encrypt_private_key(p_private_key_pem, COALESCE(p_master_password, 'default_password'));
    ELSE
        -- No PEMs provided: use placeholder key material, but we STILL require an active config
        encrypted_key_data := encode('placeholder_key', 'base64')::BYTEA;
        key_salt_data := gen_random_bytes(32);

        SELECT id
          INTO encryption_config_id_val
        FROM encryption_config
        WHERE is_active = true
        ORDER BY created_at DESC
        LIMIT 1;

        IF encryption_config_id_val IS NULL THEN
            RAISE EXCEPTION 'No active encryption_config found. Insert one (e.g., INSERT INTO encryption_config(config_name, cipher_type, iterations) VALUES (%, %, %))',
                'default_aes256', 'aes256-cbc', 100000;
        END IF;
    END IF;

    INSERT INTO certificate_authorities (
        ca_name, common_name, organization, organizational_unit, country,
        state_province, locality, email, cert_type, parent_ca_id, serial_number,
        key_algorithm, key_size, hash_algorithm,
        certificate_pem, encrypted_private_key, encryption_config_id, key_salt,
        not_before, not_after, is_root,
        path_length_constraint, key_usage, extended_key_usage,
        created_by
    ) VALUES (
        p_ca_name, p_common_name, p_organization, p_organizational_unit, p_country,
        p_state_province, p_locality, p_email, p_cert_type, p_parent_ca_id, serial_num,
        p_key_algorithm, p_key_size, p_hash_algorithm,
        COALESCE(p_certificate_pem, 'PLACEHOLDER_CERT_PEM'),
        encrypted_key_data, encryption_config_id_val, key_salt_data,
        not_before_date, not_after_date, is_root_ca,
        p_path_length_constraint, p_key_usage, p_extended_key_usage,
        p_created_by
    ) RETURNING id INTO new_ca_id;

    INSERT INTO certificate_audit_log (
        operation_type, ca_id, subject_cn, serial_number,
        operation_details, performed_by, success
    ) VALUES (
        'create_ca', new_ca_id, p_common_name, serial_num,
        jsonb_build_object(
            'ca_name', p_ca_name,
            'cert_type', p_cert_type,
            'is_root', is_root_ca,
            'key_algorithm', p_key_algorithm,
            'key_size', p_key_size
        ),
        p_created_by, true
    );

    RETURN new_ca_id;
END;
$$;


ALTER FUNCTION public.create_certificate_authority(p_ca_name character varying, p_common_name character varying, p_organization character varying, p_organizational_unit character varying, p_country character, p_state_province character varying, p_locality character varying, p_email character varying, p_cert_type public.certificate_type, p_parent_ca_id uuid, p_key_algorithm public.key_algorithm, p_key_size integer, p_hash_algorithm public.hash_algorithm, p_validity_days integer, p_key_usage text[], p_extended_key_usage text[], p_path_length_constraint integer, p_certificate_pem text, p_private_key_pem text, p_master_password text, p_created_by character varying) OWNER TO postgres;

--
-- Name: create_certificate_authority_openssl(text, text, text, text, character, text, text, text, integer, public.hash_algorithm, integer, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.create_certificate_authority_openssl(p_ca_name text, p_common_name text, p_organization text DEFAULT NULL::text, p_organizational_unit text DEFAULT NULL::text, p_country character DEFAULT NULL::bpchar, p_state_province text DEFAULT NULL::text, p_locality text DEFAULT NULL::text, p_email text DEFAULT NULL::text, p_key_bits integer DEFAULT 4096, p_hash_alg public.hash_algorithm DEFAULT 'sha256'::public.hash_algorithm, p_validity_days integer DEFAULT 3650, p_master_password text DEFAULT NULL::text, p_created_by text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpython3u SECURITY DEFINER
    AS $_$
import os, tempfile, subprocess, shutil
import plpy

# Build subject DN
parts = [f"/CN={p_common_name}"]
if p_organization: parts.append(f"/O={p_organization}")
if p_organizational_unit: parts.append(f"/OU={p_organizational_unit}")
if p_country: parts.append(f"/C={p_country}")
if p_state_province: parts.append(f"/ST={p_state_province}")
if p_locality: parts.append(f"/L={p_locality}")
subj = "".join(parts)

tmpdir = tempfile.mkdtemp(prefix="pg_ca_")
key_path = os.path.join(tmpdir, "ca.key.pem")
crt_path = os.path.join(tmpdir, "ca.crt.pem")

try:
    # Generate self-signed CA key+cert
    proc = subprocess.run(
        ["openssl", "req",
         "-new", "-x509",
         "-newkey", f"rsa:{int(p_key_bits)}",
         "-days", str(int(p_validity_days)),
         "-keyout", key_path,
         "-out", crt_path,
         "-subj", subj,
         f"-{p_hash_alg}",
         "-nodes"],
        check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    with open(key_path, "rb") as f: key_pem = f.read().decode("utf-8")
    with open(crt_path, "rb") as f: crt_pem = f.read().decode("utf-8")

    # Insert via SQL function (prepared)
    q = """
        SELECT create_certificate_authority(
            p_ca_name := $1,
            p_common_name := $2,
            p_organization := $3,
            p_organizational_unit := $4,
            p_country := $5,
            p_state_province := $6,
            p_locality := $7,
            p_email := $8,
            p_cert_type := 'root_ca',
            p_parent_ca_id := NULL,
            p_key_algorithm := 'rsa',
            p_key_size := $9,
            p_hash_algorithm := $10,
            p_validity_days := $11,
            p_certificate_pem := $12,
            p_private_key_pem := $13,
            p_master_password := $14,
            p_created_by := $15
        ) AS id;
    """
    plan = plpy.prepare(q, [
        "text","text","text","text","text","text","text","text",
        "integer","hash_algorithm","integer","text","text","text","text"
    ])
    rv = plpy.execute(plan, [
        p_ca_name, p_common_name, p_organization, p_organizational_unit, p_country,
        p_state_province, p_locality, p_email, int(p_key_bits), p_hash_alg,
        int(p_validity_days), crt_pem, key_pem, p_master_password, p_created_by
    ])
    if len(rv) == 0:
        raise plpy.Error("create_certificate_authority returned no rows")
    return rv[0]["id"]

except subprocess.CalledProcessError as e:
    raise plpy.Error(f"OpenSSL failed: {e.stderr.decode('utf-8', 'ignore')}")
finally:
    try: shutil.rmtree(tmpdir)
    except Exception: pass
$_$;


ALTER FUNCTION public.create_certificate_authority_openssl(p_ca_name text, p_common_name text, p_organization text, p_organizational_unit text, p_country character, p_state_province text, p_locality text, p_email text, p_key_bits integer, p_hash_alg public.hash_algorithm, p_validity_days integer, p_master_password text, p_created_by text) OWNER TO postgres;

--
-- Name: decrypt_private_key(bytea, bytea, text, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.decrypt_private_key(encrypted_key bytea, key_salt bytea, master_password text, config_id uuid) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
    encryption_cfg RECORD;
    derived_key BYTEA;
    decrypted_data BYTEA;
BEGIN
    -- Fetch encryption configuration
    SELECT * INTO encryption_cfg
    FROM encryption_config
    WHERE id = config_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Encryption configuration not found';
    END IF;

    -- Derive key (same method as encryption)
    derived_key := digest(master_password || encode(key_salt, 'hex'), 'sha256');

    -- Decrypt (CBC)
    CASE encryption_cfg.cipher_type
        WHEN 'aes256-cbc' THEN
            decrypted_data := decrypt_iv(encrypted_key, derived_key, key_salt, 'aes-cbc');
        WHEN 'aes256-gcm' THEN
            decrypted_data := decrypt_iv(encrypted_key, derived_key, key_salt, 'aes-cbc');
        ELSE
            decrypted_data := decrypt_iv(encrypted_key, derived_key, key_salt, 'aes-cbc');
    END CASE;

    RETURN convert_from(decrypted_data, 'UTF8');

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO certificate_audit_log (
            operation_type, operation_details, performed_at, success
        ) VALUES (
            'decrypt_failed', 
            jsonb_build_object('config_id', config_id, 'error', SQLERRM),
            NOW(), 
            false
        );
        RAISE EXCEPTION 'Failed to decrypt private key: %', SQLERRM;
END;
$$;


ALTER FUNCTION public.decrypt_private_key(encrypted_key bytea, key_salt bytea, master_password text, config_id uuid) OWNER TO postgres;

--
-- Name: encrypt_private_key(text, text, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.encrypt_private_key(private_key_pem text, master_password text, config_id uuid DEFAULT NULL::uuid) RETURNS TABLE(encrypted_key bytea, salt bytea, config_used uuid)
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
    encryption_cfg RECORD;
    key_salt BYTEA;
    derived_key BYTEA;
    encrypted_data BYTEA;
BEGIN
    -- Pick active encryption config (explicit or default active)
    IF config_id IS NULL THEN
        SELECT * INTO encryption_cfg
        FROM encryption_config
        WHERE is_active = true
        ORDER BY created_at DESC
        LIMIT 1;
    ELSE
        SELECT * INTO encryption_cfg
        FROM encryption_config
        WHERE id = config_id AND is_active = true;
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'No valid encryption configuration found';
    END IF;

    -- Random salt (also used as IV here)
    key_salt := gen_random_bytes(encryption_cfg.salt_length);

    -- Derive key (simple digest derivation; upgrade to real PBKDF2 if desired)
    derived_key := digest(master_password || encode(key_salt, 'hex'), 'sha256');

    -- Encrypt with AES-CBC (pgcrypto has no GCM)
    CASE encryption_cfg.cipher_type
        WHEN 'aes256-cbc' THEN
            encrypted_data := encrypt_iv(private_key_pem::BYTEA, derived_key, key_salt, 'aes-cbc');
        WHEN 'aes256-gcm' THEN
            encrypted_data := encrypt_iv(private_key_pem::BYTEA, derived_key, key_salt, 'aes-cbc');
        ELSE
            encrypted_data := encrypt_iv(private_key_pem::BYTEA, derived_key, key_salt, 'aes-cbc');
    END CASE;

    RETURN QUERY SELECT encrypted_data, key_salt, encryption_cfg.id;
END;
$$;


ALTER FUNCTION public.encrypt_private_key(private_key_pem text, master_password text, config_id uuid) OWNER TO postgres;

--
-- Name: generate_openssl_ca_command(uuid, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.generate_openssl_ca_command(ca_id uuid, output_cert_path text DEFAULT '/tmp/cert.pem'::text, output_key_path text DEFAULT '/tmp/key.pem'::text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    ca_record RECORD;
    openssl_cmd TEXT;
    subject_dn TEXT;
BEGIN
    SELECT * INTO ca_record
    FROM certificate_authorities
    WHERE id = ca_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'CA not found';
    END IF;

    subject_dn := '/CN=' || ca_record.common_name;
    IF ca_record.organization IS NOT NULL THEN
        subject_dn := subject_dn || '/O=' || ca_record.organization;
    END IF;
    IF ca_record.organizational_unit IS NOT NULL THEN
        subject_dn := subject_dn || '/OU=' || ca_record.organizational_unit;
    END IF;
    IF ca_record.country IS NOT NULL THEN
        subject_dn := subject_dn || '/C=' || ca_record.country;
    END IF;
    IF ca_record.state_province IS NOT NULL THEN
        subject_dn := subject_dn || '/ST=' || ca_record.state_province;
    END IF;
    IF ca_record.locality IS NOT NULL THEN
        subject_dn := subject_dn || '/L=' || ca_record.locality;
    END IF;

    openssl_cmd := format(
        'openssl req -new -x509 -days %s -key %s -out %s -subj "%s" -%s',
        EXTRACT(day FROM (ca_record.not_after - ca_record.not_before)),
        output_key_path,
        output_cert_path,
        subject_dn,
        ca_record.hash_algorithm
    );

    RETURN openssl_cmd;
END;
$$;


ALTER FUNCTION public.generate_openssl_ca_command(ca_id uuid, output_cert_path text, output_key_path text) OWNER TO postgres;

--
-- Name: generate_openssl_sign_command(uuid, text, text, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.generate_openssl_sign_command(ca_id uuid, csr_path text, output_cert_path text DEFAULT '/tmp/signed_cert.pem'::text, ca_cert_path text DEFAULT '/tmp/ca_cert.pem'::text, ca_key_path text DEFAULT '/tmp/ca_key.pem'::text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    ca_record RECORD;
    openssl_cmd TEXT;
BEGIN
    SELECT * INTO ca_record
    FROM certificate_authorities
    WHERE id = ca_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'CA not found';
    END IF;

    openssl_cmd := format(
        'openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days %s -%s',
        csr_path,
        ca_cert_path,
        ca_key_path,
        output_cert_path,
        365,
        ca_record.hash_algorithm
    );

    RETURN openssl_cmd;
END;
$$;


ALTER FUNCTION public.generate_openssl_sign_command(ca_id uuid, csr_path text, output_cert_path text, ca_cert_path text, ca_key_path text) OWNER TO postgres;

--
-- Name: generate_serial_number(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.generate_serial_number() RETURNS numeric
    LANGUAGE plpgsql
    AS $$
DECLARE
    next_serial NUMERIC(39,0);
BEGIN
    -- Random 0 .. 10^38-1
    next_serial := (random() * power(10, 38))::NUMERIC(39,0);

    -- Keep trying until it's unused across both tables (very unlikely loop)
    WHILE EXISTS (
        SELECT 1 FROM certificates WHERE serial_number = next_serial
        UNION ALL
        SELECT 1 FROM certificate_authorities WHERE serial_number = next_serial
    ) LOOP
        next_serial := (random() * power(10, 38))::NUMERIC(39,0);
    END LOOP;

    RETURN next_serial;
END;
$$;


ALTER FUNCTION public.generate_serial_number() OWNER TO postgres;

--
-- Name: issue_certificate(uuid, character varying, text[], character varying, character varying, character, character varying, character varying, character varying, public.certificate_type, public.key_algorithm, integer, public.hash_algorithm, integer, text[], text[], uuid, text, text, text, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.issue_certificate(p_issuing_ca_id uuid, p_common_name character varying, p_subject_alternative_names text[] DEFAULT NULL::text[], p_organization character varying DEFAULT NULL::character varying, p_organizational_unit character varying DEFAULT NULL::character varying, p_country character DEFAULT NULL::bpchar, p_state_province character varying DEFAULT NULL::character varying, p_locality character varying DEFAULT NULL::character varying, p_email character varying DEFAULT NULL::character varying, p_cert_type public.certificate_type DEFAULT 'end_entity'::public.certificate_type, p_key_algorithm public.key_algorithm DEFAULT 'rsa'::public.key_algorithm, p_key_size integer DEFAULT 2048, p_hash_algorithm public.hash_algorithm DEFAULT 'sha256'::public.hash_algorithm, p_validity_days integer DEFAULT 365, p_key_usage text[] DEFAULT ARRAY['digitalSignature'::text, 'keyEncipherment'::text], p_extended_key_usage text[] DEFAULT ARRAY['serverAuth'::text], p_template_id uuid DEFAULT NULL::uuid, p_certificate_pem text DEFAULT NULL::text, p_private_key_pem text DEFAULT NULL::text, p_master_password text DEFAULT NULL::text, p_created_by character varying DEFAULT NULL::character varying) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    new_cert_id UUID;
    serial_num NUMERIC(39,0);
    not_before_date TIMESTAMPTZ;
    not_after_date TIMESTAMPTZ;
    template_rec RECORD;
    encrypted_key_data BYTEA;
    key_salt_data BYTEA;
    encryption_config_id_val UUID;
BEGIN
    -- Ensure issuing CA exists and is active
    IF NOT EXISTS (
        SELECT 1 FROM certificate_authorities 
        WHERE id = p_issuing_ca_id AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'Issuing CA not found or not active';
    END IF;

    -- Apply template defaults if provided
    IF p_template_id IS NOT NULL THEN
        SELECT * INTO template_rec
        FROM certificate_templates
        WHERE id = p_template_id;

        IF FOUND THEN
            p_cert_type          := COALESCE(p_cert_type,          template_rec.cert_type);
            p_key_algorithm      := COALESCE(p_key_algorithm,      template_rec.key_algorithm);
            p_key_size           := COALESCE(p_key_size,           template_rec.key_size);
            p_hash_algorithm     := COALESCE(p_hash_algorithm,     template_rec.hash_algorithm);
            p_validity_days      := COALESCE(p_validity_days,      template_rec.validity_period_days);
            p_key_usage          := COALESCE(p_key_usage,          template_rec.key_usage);
            p_extended_key_usage := COALESCE(p_extended_key_usage, template_rec.extended_key_usage);
        END IF;
    END IF;

    serial_num := generate_serial_number();

    not_before_date := NOW();
    not_after_date  := NOW() + (p_validity_days || ' days')::INTERVAL;

    IF p_private_key_pem IS NOT NULL THEN
        SELECT encrypted_key, salt, config_used 
          INTO encrypted_key_data, key_salt_data, encryption_config_id_val
        FROM encrypt_private_key(p_private_key_pem, COALESCE(p_master_password, 'default_password'));
    ELSE
        encrypted_key_data := encode('placeholder_key', 'base64')::BYTEA;
        key_salt_data := gen_random_bytes(32);

        SELECT id
          INTO encryption_config_id_val
        FROM encryption_config
        WHERE is_active = true
        ORDER BY created_at DESC
        LIMIT 1;

        IF encryption_config_id_val IS NULL THEN
            RAISE EXCEPTION 'No active encryption_config found. Insert one (e.g., INSERT INTO encryption_config(config_name, cipher_type, iterations) VALUES (%, %, %))',
                'default_aes256', 'aes256-cbc', 100000;
        END IF;
    END IF;

    INSERT INTO certificates (
        issuing_ca_id, common_name, subject_alternative_names,
        organization, organizational_unit, country, state_province, locality, email,
        cert_type, serial_number, key_algorithm, key_size, hash_algorithm,
        certificate_pem, encrypted_private_key, encryption_config_id, key_salt,
        not_before, not_after, key_usage, extended_key_usage, created_by
    ) VALUES (
        p_issuing_ca_id, p_common_name, p_subject_alternative_names,
        p_organization, p_organizational_unit, p_country, p_state_province, p_locality, p_email,
        p_cert_type, serial_num, p_key_algorithm, p_key_size, p_hash_algorithm,
        COALESCE(p_certificate_pem, 'PLACEHOLDER_CERT_PEM'),
        encrypted_key_data, encryption_config_id_val, key_salt_data,
        not_before_date, not_after_date, p_key_usage, p_extended_key_usage, p_created_by
    ) RETURNING id INTO new_cert_id;

    INSERT INTO certificate_audit_log (
        operation_type, certificate_id, subject_cn, serial_number,
        operation_details, performed_by, success
    ) VALUES (
        'issue_cert', new_cert_id, p_common_name, serial_num,
        jsonb_build_object(
            'issuing_ca_id', p_issuing_ca_id,
            'cert_type', p_cert_type,
            'key_algorithm', p_key_algorithm,
            'validity_days', p_validity_days
        ),
        p_created_by, true
    );

    RETURN new_cert_id;
END;
$$;


ALTER FUNCTION public.issue_certificate(p_issuing_ca_id uuid, p_common_name character varying, p_subject_alternative_names text[], p_organization character varying, p_organizational_unit character varying, p_country character, p_state_province character varying, p_locality character varying, p_email character varying, p_cert_type public.certificate_type, p_key_algorithm public.key_algorithm, p_key_size integer, p_hash_algorithm public.hash_algorithm, p_validity_days integer, p_key_usage text[], p_extended_key_usage text[], p_template_id uuid, p_certificate_pem text, p_private_key_pem text, p_master_password text, p_created_by character varying) OWNER TO postgres;

--
-- Name: issue_certificate_openssl(uuid, text, text, text[], text, text, character, text, text, text, integer, public.hash_algorithm, integer, text[], text[], text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.issue_certificate_openssl(p_issuing_ca_id uuid, p_common_name text, p_master_password text, p_subject_alternative_names text[] DEFAULT NULL::text[], p_organization text DEFAULT NULL::text, p_organizational_unit text DEFAULT NULL::text, p_country character DEFAULT NULL::bpchar, p_state_province text DEFAULT NULL::text, p_locality text DEFAULT NULL::text, p_email text DEFAULT NULL::text, p_key_bits integer DEFAULT 2048, p_hash_alg public.hash_algorithm DEFAULT 'sha256'::public.hash_algorithm, p_validity_days integer DEFAULT 825, p_key_usage text[] DEFAULT ARRAY['digitalSignature'::text, 'keyEncipherment'::text], p_extended_key_usage text[] DEFAULT ARRAY['serverAuth'::text], p_created_by text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpython3u SECURITY DEFINER
    AS $_$
import os, tempfile, subprocess, shutil
import plpy

# 1) Fetch CA materials
plan_ca = plpy.prepare("""
    SELECT certificate_pem, encrypted_private_key, key_salt, encryption_config_id
    FROM certificate_authorities
    WHERE id = $1 AND status = 'active'
""", ["uuid"])
rowset = plpy.execute(plan_ca, [p_issuing_ca_id])
if len(rowset) == 0:
    raise plpy.Error("Issuing CA not found or not active")

ca_cert_pem = rowset[0]["certificate_pem"]
enc_key     = rowset[0]["encrypted_private_key"]
key_salt    = rowset[0]["key_salt"]
cfg_id      = rowset[0]["encryption_config_id"]

# 2) Decrypt CA key using SQL function
plan_dec = plpy.prepare("SELECT decrypt_private_key($1, $2, $3, $4) AS key_pem",
                        ["bytea","bytea","text","uuid"])
dec = plpy.execute(plan_dec, [enc_key, key_salt, p_master_password, cfg_id])
if len(dec) == 0 or dec[0]["key_pem"] is None:
    raise plpy.Error("Failed to decrypt CA private key (bad password/config?)")
ca_key_pem = dec[0]["key_pem"]

# 3) Temp workspace
tmpdir = tempfile.mkdtemp(prefix="pg_cert_")
ca_key_path   = os.path.join(tmpdir, "ca.key.pem")
ca_crt_path   = os.path.join(tmpdir, "ca.crt.pem")
leaf_key_path = os.path.join(tmpdir, "leaf.key.pem")
leaf_csr_path = os.path.join(tmpdir, "leaf.csr.pem")
leaf_crt_path = os.path.join(tmpdir, "leaf.crt.pem")
ext_path      = os.path.join(tmpdir, "ext.cnf")

try:
    # Write CA materials
    with open(ca_key_path, "w") as f: f.write(ca_key_pem)
    with open(ca_crt_path, "w") as f: f.write(ca_cert_pem)

    # 4) Build OpenSSL request/extension config without f-strings
    lines = []
    lines += ["[ req]", "distinguished_name = dn", "prompt = no",
              "default_md = " + (p_hash_alg if p_hash_alg else "sha256"),
              "req_extensions = req_ext", ""]
    lines += ["[ dn]"]  # space before ] is harmless; keep literal exactness
    lines += ["CN = " + p_common_name]
    if p_organization:        lines += ["O = " + p_organization]
    if p_organizational_unit: lines += ["OU = " + p_organizational_unit]
    if p_country:             lines += ["C = " + p_country]
    if p_state_province:      lines += ["ST = " + p_state_province]
    if p_locality:            lines += ["L = " + p_locality]
    if p_email:               lines += ["emailAddress = " + p_email]
    lines += ["", "[ req_ext]", "basicConstraints = CA:FALSE"]

    # Key Usage / EKU
    ku  = ",".join(p_key_usage) if p_key_usage else "digitalSignature,keyEncipherment"
    eku = ",".join(p_extended_key_usage) if p_extended_key_usage else "serverAuth"
    lines += ["keyUsage = " + ku, "extendedKeyUsage = " + eku]

    # SANs
    alt_lines = []
    if p_subject_alternative_names:
        for i, name in enumerate(p_subject_alternative_names, start=1):
            alt_lines.append("DNS.%d = %s" % (i, name))
    if alt_lines:
        lines += ["subjectAltName = @alt_names", "", "[ alt_names ]"] + alt_lines

    ext_content = "\n".join(lines) + "\n"
    with open(ext_path, "w") as f: f.write(ext_content)

    # 5) Generate leaf key + CSR
    subprocess.run(
        ["openssl", "req",
         "-new", "-newkey", "rsa:%d" % int(p_key_bits),
         "-nodes",
         "-keyout", leaf_key_path,
         "-out", leaf_csr_path,
         "-config", ext_path],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # 6) Sign CSR with CA
    subprocess.run(
        ["openssl", "x509", "-req",
         "-in", leaf_csr_path,
         "-CA", ca_crt_path,
         "-CAkey", ca_key_path,
         "-CAcreateserial",
         "-out", leaf_crt_path,
         "-days", str(int(p_validity_days)),
         "-" + (p_hash_alg if p_hash_alg else "sha256"),
         "-extfile", ext_path,
         "-extensions", "req_ext"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    with open(leaf_key_path, "rb") as f: leaf_key_pem = f.read().decode("utf-8")
    with open(leaf_crt_path, "rb") as f: leaf_crt_pem = f.read().decode("utf-8")

    # 7) Insert via SQL function (prepare + cast enum via ::hash_algorithm)
    q = """
        SELECT issue_certificate(
            p_issuing_ca_id := $1,
            p_common_name := $2,
            p_subject_alternative_names := $3,
            p_organization := $4,
            p_organizational_unit := $5,
            p_country := $6,
            p_state_province := $7,
            p_locality := $8,
            p_email := $9,
            p_cert_type := 'server',
            p_key_algorithm := 'rsa',
            p_key_size := $10,
            p_hash_algorithm := $11::hash_algorithm,
            p_validity_days := $12,
            p_key_usage := $13,
            p_extended_key_usage := $14,
            p_certificate_pem := $15,
            p_private_key_pem := $16,
            p_master_password := $17,
            p_created_by := $18
        ) AS id;
    """
    plan = plpy.prepare(q, [
        "uuid","text","text[]","text","text","text","text","text","text",
        "integer","text","integer","text[]","text[]","text","text","text","text"
    ])
    rv = plpy.execute(plan, [
        p_issuing_ca_id, p_common_name, p_subject_alternative_names,
        p_organization, p_organizational_unit, p_country, p_state_province, p_locality, p_email,
        int(p_key_bits), str(p_hash_alg), int(p_validity_days),
        p_key_usage, p_extended_key_usage,
        leaf_crt_pem, leaf_key_pem, p_master_password, p_created_by
    ])
    if len(rv) == 0:
        raise plpy.Error("issue_certificate returned no rows")
    return rv[0]["id"]

except subprocess.CalledProcessError as e:
    raise plpy.Error("OpenSSL failed: " + e.stderr.decode("utf-8", "ignore"))
finally:
    try: shutil.rmtree(tmpdir)
    except Exception: pass
$_$;


ALTER FUNCTION public.issue_certificate_openssl(p_issuing_ca_id uuid, p_common_name text, p_master_password text, p_subject_alternative_names text[], p_organization text, p_organizational_unit text, p_country character, p_state_province text, p_locality text, p_email text, p_key_bits integer, p_hash_alg public.hash_algorithm, p_validity_days integer, p_key_usage text[], p_extended_key_usage text[], p_created_by text) OWNER TO postgres;

--
-- Name: revoke_certificate(uuid, public.revocation_reason, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.revoke_certificate(p_certificate_id uuid, p_revocation_reason public.revocation_reason DEFAULT 'unspecified'::public.revocation_reason, p_performed_by character varying DEFAULT NULL::character varying) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    cert_record RECORD;
BEGIN
    SELECT * INTO cert_record
    FROM certificates
    WHERE id = p_certificate_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Certificate not found';
    END IF;

    IF cert_record.status = 'revoked' THEN
        RAISE EXCEPTION 'Certificate already revoked';
    END IF;

    UPDATE certificates 
    SET status = 'revoked',
        revoked_at = NOW(),
        revocation_reason = p_revocation_reason,
        updated_at = NOW()
    WHERE id = p_certificate_id;

    INSERT INTO crl_entries (
        issuing_ca_id, certificate_id, serial_number,
        revocation_date, revocation_reason
    ) VALUES (
        cert_record.issuing_ca_id, p_certificate_id, cert_record.serial_number,
        NOW(), p_revocation_reason
    );

    INSERT INTO certificate_audit_log (
        operation_type, certificate_id, subject_cn, serial_number,
        operation_details, performed_by, success
    ) VALUES (
        'revoke_cert', p_certificate_id, cert_record.common_name, cert_record.serial_number,
        jsonb_build_object('reason', p_revocation_reason),
        p_performed_by, true
    );

    RETURN true;
END;
$$;


ALTER FUNCTION public.revoke_certificate(p_certificate_id uuid, p_revocation_reason public.revocation_reason, p_performed_by character varying) OWNER TO postgres;

--
-- Name: update_ca_pem(uuid, text, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_ca_pem(p_ca_id uuid, p_certificate_pem text, p_private_key_pem text DEFAULT NULL::text, p_master_password text DEFAULT NULL::text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    encrypted_key_data BYTEA;
    key_salt_data BYTEA;
    encryption_config_id_val UUID;
BEGIN
    IF p_private_key_pem IS NOT NULL THEN
        SELECT encrypted_key, salt, config_used 
          INTO encrypted_key_data, key_salt_data, encryption_config_id_val
        FROM encrypt_private_key(p_private_key_pem, COALESCE(p_master_password, 'default_password'));

        UPDATE certificate_authorities 
        SET certificate_pem       = p_certificate_pem,
            encrypted_private_key = encrypted_key_data,
            key_salt              = key_salt_data,
            encryption_config_id  = encryption_config_id_val,
            updated_at            = NOW()
        WHERE id = p_ca_id;
    ELSE
        UPDATE certificate_authorities 
        SET certificate_pem = p_certificate_pem,
            updated_at      = NOW()
        WHERE id = p_ca_id;
    END IF;

    INSERT INTO certificate_audit_log (
        operation_type, ca_id, operation_details, success
    ) VALUES (
        'update_ca_pem', p_ca_id, 
        jsonb_build_object('has_private_key', p_private_key_pem IS NOT NULL),
        true
    );

    RETURN true;
END;
$$;


ALTER FUNCTION public.update_ca_pem(p_ca_id uuid, p_certificate_pem text, p_private_key_pem text, p_master_password text) OWNER TO postgres;

--
-- Name: update_certificate_pem(uuid, text, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_certificate_pem(p_cert_id uuid, p_certificate_pem text, p_private_key_pem text DEFAULT NULL::text, p_master_password text DEFAULT NULL::text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    encrypted_key_data BYTEA;
    key_salt_data BYTEA;
    encryption_config_id_val UUID;
BEGIN
    IF p_private_key_pem IS NOT NULL THEN
        SELECT encrypted_key, salt, config_used 
          INTO encrypted_key_data, key_salt_data, encryption_config_id_val
        FROM encrypt_private_key(p_private_key_pem, COALESCE(p_master_password, 'default_password'));

        UPDATE certificates 
        SET certificate_pem       = p_certificate_pem,
            encrypted_private_key = encrypted_key_data,
            key_salt              = key_salt_data,
            encryption_config_id  = encryption_config_id_val,
            updated_at            = NOW()
        WHERE id = p_cert_id;
    ELSE
        UPDATE certificates 
        SET certificate_pem = p_certificate_pem,
            updated_at      = NOW()
        WHERE id = p_cert_id;
    END IF;

    INSERT INTO certificate_audit_log (
        operation_type, certificate_id, operation_details, success
    ) VALUES (
        'update_pem', p_cert_id, 
        jsonb_build_object('has_private_key', p_private_key_pem IS NOT NULL),
        true
    );

    RETURN true;
END;
$$;


ALTER FUNCTION public.update_certificate_pem(p_cert_id uuid, p_certificate_pem text, p_private_key_pem text, p_master_password text) OWNER TO postgres;

