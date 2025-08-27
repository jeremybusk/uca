--
-- Name: cert_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.cert_status AS ENUM (
    'active',
    'revoked',
    'expired',
    'pending',
    'suspended'
);


ALTER TYPE public.cert_status OWNER TO postgres;

--
-- Name: certificate_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.certificate_type AS ENUM (
    'root_ca',
    'intermediate_ca',
    'end_entity',
    'server',
    'client',
    'code_signing',
    'email',
    'timestamp'
);


ALTER TYPE public.certificate_type OWNER TO postgres;

--
-- Name: cipher_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.cipher_type AS ENUM (
    'aes256-cbc',
    'aes256-gcm',
    'aes192-cbc',
    'aes128-cbc',
    'des3-cbc'
);


ALTER TYPE public.cipher_type OWNER TO postgres;

--
-- Name: hash_algorithm; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.hash_algorithm AS ENUM (
    'sha256',
    'sha384',
    'sha512',
    'sha1'
);


ALTER TYPE public.hash_algorithm OWNER TO postgres;

--
-- Name: key_algorithm; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.key_algorithm AS ENUM (
    'rsa',
    'ecdsa',
    'ed25519',
    'dsa'
);


ALTER TYPE public.key_algorithm OWNER TO postgres;

--
-- Name: revocation_reason; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.revocation_reason AS ENUM (
    'unspecified',
    'key_compromise',
    'ca_compromise',
    'affiliation_changed',
    'superseded',
    'cessation_of_operation',
    'certificate_hold',
    'remove_from_crl',
    'privilege_withdrawn',
    'aa_compromise'
);


ALTER TYPE public.revocation_reason OWNER TO postgres;

