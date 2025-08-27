--
-- Name: certificate_audit_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.certificate_audit_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    operation_type character varying(50) NOT NULL,
    certificate_id uuid,
    ca_id uuid,
    subject_cn character varying(255),
    serial_number numeric(39,0),
    operation_details jsonb,
    performed_by character varying(255),
    performed_at timestamp with time zone DEFAULT now(),
    client_ip inet,
    success boolean NOT NULL
);


ALTER TABLE public.certificate_audit_log OWNER TO postgres;

--
-- Name: certificate_authorities; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.certificate_authorities (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ca_name character varying(255) NOT NULL,
    common_name character varying(255) NOT NULL,
    organization character varying(255),
    organizational_unit character varying(255),
    country character(2),
    state_province character varying(255),
    locality character varying(255),
    email character varying(255),
    cert_type public.certificate_type NOT NULL,
    parent_ca_id uuid,
    serial_number numeric(39,0) NOT NULL,
    key_algorithm public.key_algorithm NOT NULL,
    key_size integer NOT NULL,
    hash_algorithm public.hash_algorithm NOT NULL,
    certificate_pem text NOT NULL,
    encrypted_private_key bytea NOT NULL,
    encryption_config_id uuid NOT NULL,
    key_salt bytea NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    status public.cert_status DEFAULT 'active'::public.cert_status,
    is_root boolean DEFAULT false,
    path_length_constraint integer,
    key_usage text[],
    extended_key_usage text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    created_by character varying(255),
    CONSTRAINT root_ca_check CHECK ((((is_root = true) AND (parent_ca_id IS NULL)) OR ((is_root = false) AND (parent_ca_id IS NOT NULL)))),
    CONSTRAINT valid_dates CHECK ((not_before < not_after))
);


ALTER TABLE public.certificate_authorities OWNER TO postgres;

--
-- Name: certificate_templates; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.certificate_templates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    template_name character varying(255) NOT NULL,
    cert_type public.certificate_type NOT NULL,
    key_algorithm public.key_algorithm NOT NULL,
    key_size integer NOT NULL,
    hash_algorithm public.hash_algorithm NOT NULL,
    validity_period_days integer NOT NULL,
    key_usage text[] NOT NULL,
    extended_key_usage text[],
    subject_template jsonb,
    san_template jsonb,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.certificate_templates OWNER TO postgres;

--
-- Name: certificates; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.certificates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    issuing_ca_id uuid NOT NULL,
    issuing_ca_uuid uuid GENERATED ALWAYS AS (issuing_ca_id) STORED,
    common_name character varying(255) NOT NULL,
    subject_alternative_names text[],
    organization character varying(255),
    organizational_unit character varying(255),
    country character(2),
    state_province character varying(255),
    locality character varying(255),
    email character varying(255),
    cert_type public.certificate_type NOT NULL,
    serial_number numeric(39,0) NOT NULL,
    key_algorithm public.key_algorithm NOT NULL,
    key_size integer NOT NULL,
    hash_algorithm public.hash_algorithm NOT NULL,
    certificate_pem text NOT NULL,
    encrypted_private_key bytea,
    encryption_config_id uuid,
    key_salt bytea,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    key_usage text[],
    extended_key_usage text[],
    status public.cert_status DEFAULT 'active'::public.cert_status,
    revoked_at timestamp with time zone,
    revocation_reason public.revocation_reason,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    created_by character varying(255),
    CONSTRAINT valid_cert_dates CHECK ((not_before < not_after))
);


ALTER TABLE public.certificates OWNER TO postgres;

--
-- Name: crl_entries; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.crl_entries (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    issuing_ca_id uuid NOT NULL,
    issuing_ca_uuid uuid GENERATED ALWAYS AS (issuing_ca_id) STORED,
    certificate_id uuid,
    serial_number numeric(39,0) NOT NULL,
    revocation_date timestamp with time zone NOT NULL,
    revocation_reason public.revocation_reason NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.crl_entries OWNER TO postgres;

--
-- Name: encryption_config; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.encryption_config (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    config_name character varying(100) NOT NULL,
    cipher_type public.cipher_type NOT NULL,
    key_derivation_function character varying(50) DEFAULT 'pbkdf2'::character varying,
    iterations integer DEFAULT 100000,
    salt_length integer DEFAULT 32,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    is_active boolean DEFAULT true
);


ALTER TABLE public.encryption_config OWNER TO postgres;


-- COPY data if applicable


--
-- Name: certificate_audit_log certificate_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_audit_log
    ADD CONSTRAINT certificate_audit_log_pkey PRIMARY KEY (id);


--
-- Name: certificate_authorities certificate_authorities_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_pkey PRIMARY KEY (id);


--
-- Name: certificate_authorities certificate_authorities_serial_number_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_serial_number_key UNIQUE (serial_number);


--
-- Name: certificate_templates certificate_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_templates
    ADD CONSTRAINT certificate_templates_pkey PRIMARY KEY (id);


--
-- Name: certificate_templates certificate_templates_template_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_templates
    ADD CONSTRAINT certificate_templates_template_name_key UNIQUE (template_name);


--
-- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


--
-- Name: crl_entries crl_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.crl_entries
    ADD CONSTRAINT crl_entries_pkey PRIMARY KEY (id);


--
-- Name: encryption_config encryption_config_config_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryption_config
    ADD CONSTRAINT encryption_config_config_name_key UNIQUE (config_name);


--
-- Name: encryption_config encryption_config_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryption_config
    ADD CONSTRAINT encryption_config_pkey PRIMARY KEY (id);


--
-- Name: idx_audit_cert; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_audit_cert ON public.certificate_audit_log USING btree (certificate_id);


--
-- Name: idx_audit_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_audit_timestamp ON public.certificate_audit_log USING btree (performed_at);


--
-- Name: idx_ca_parent; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ca_parent ON public.certificate_authorities USING btree (parent_ca_id);


--
-- Name: idx_ca_serial; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ca_serial ON public.certificate_authorities USING btree (serial_number);


--
-- Name: idx_certificates_cn; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_cn ON public.certificates USING btree (common_name);


--
-- Name: idx_certificates_expiry; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_expiry ON public.certificates USING btree (not_after);


--
-- Name: idx_certificates_issuing_ca; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_issuing_ca ON public.certificates USING btree (issuing_ca_id);


--
-- Name: idx_certificates_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_status ON public.certificates USING btree (status);


--
-- Name: idx_crl_ca; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_crl_ca ON public.crl_entries USING btree (issuing_ca_id);


--
-- Name: ux_certificates_issuing_ca_serial; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ux_certificates_issuing_ca_serial ON public.certificates USING btree (issuing_ca_uuid, serial_number);


--
-- Name: ux_crl_entries_issuing_ca_serial; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ux_crl_entries_issuing_ca_serial ON public.crl_entries USING btree (issuing_ca_uuid, serial_number);


--
-- Name: certificate_authorities certificate_authorities_encryption_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_encryption_config_id_fkey FOREIGN KEY (encryption_config_id) REFERENCES public.encryption_config(id);


--
-- Name: certificate_authorities certificate_authorities_parent_ca_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_parent_ca_id_fkey FOREIGN KEY (parent_ca_id) REFERENCES public.certificate_authorities(id);


--
-- Name: certificates certificates_encryption_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_encryption_config_id_fkey FOREIGN KEY (encryption_config_id) REFERENCES public.encryption_config(id);


--
-- Name: certificates certificates_issuing_ca_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_issuing_ca_id_fkey FOREIGN KEY (issuing_ca_id) REFERENCES public.certificate_authorities(id);


--
-- Name: crl_entries crl_entries_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.crl_entries
    ADD CONSTRAINT crl_entries_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id);


--
-- Name: crl_entries crl_entries_issuing_ca_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.crl_entries
    ADD CONSTRAINT crl_entries_issuing_ca_id_fkey FOREIGN KEY (issuing_ca_id) REFERENCES public.certificate_authorities(id);


--
-- PostgreSQL database dump complete
--

