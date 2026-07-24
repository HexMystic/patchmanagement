--
-- PostgreSQL database dump
--

\restrict aYe6U0sfIj866WgTVImAvgHXN8IwUXwDmGxZKQqJwBH5IwkwIb0v3LhOsJ5BX7I

-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: __EFMigrationsHistory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."__EFMigrationsHistory" (
    migration_id character varying(150) NOT NULL,
    product_version character varying(32) NOT NULL
);


--
-- Name: advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisories (
    id uuid NOT NULL,
    source text NOT NULL,
    external_id text NOT NULL,
    title text NOT NULL,
    severity text NOT NULL,
    published_at timestamp with time zone,
    withdrawn_at timestamp with time zone,
    cvss_base_score double precision,
    cvss_vector text,
    cvss_version text,
    cvss_source text,
    kev_listed boolean,
    kev_date_added date,
    kev_due_date date,
    kev_known_ransomware_use boolean,
    epss_score double precision,
    epss_percentile double precision,
    epss_scored_at timestamp with time zone,
    provenance jsonb NOT NULL,
    source_metadata jsonb,
    raw_ref text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_advisories_cvss_base_score CHECK (((cvss_base_score IS NULL) OR ((cvss_base_score >= (0)::double precision) AND (cvss_base_score <= (10)::double precision)))),
    CONSTRAINT ck_advisories_cvss_source CHECK (((cvss_source IS NULL) OR (cvss_source = ANY (ARRAY['nvd'::text, 'kev'::text, 'epss'::text, 'usn'::text, 'rhsa'::text, 'msrc'::text, 'wsusscn2'::text])))),
    CONSTRAINT ck_advisories_cvss_version CHECK (((cvss_version IS NULL) OR (cvss_version = ANY (ARRAY['2.0'::text, '3.0'::text, '3.1'::text, '4.0'::text])))),
    CONSTRAINT ck_advisories_epss_percentile CHECK (((epss_percentile IS NULL) OR ((epss_percentile >= (0)::double precision) AND (epss_percentile <= (1)::double precision)))),
    CONSTRAINT ck_advisories_epss_score CHECK (((epss_score IS NULL) OR ((epss_score >= (0)::double precision) AND (epss_score <= (1)::double precision)))),
    CONSTRAINT ck_advisories_provenance_non_empty CHECK (((jsonb_typeof(provenance) = 'array'::text) AND (jsonb_array_length(provenance) >= 1))),
    CONSTRAINT ck_advisories_severity CHECK ((severity = ANY (ARRAY['none'::text, 'low'::text, 'medium'::text, 'high'::text, 'critical'::text, 'unknown'::text]))),
    CONSTRAINT ck_advisories_source CHECK ((source = ANY (ARRAY['nvd'::text, 'usn'::text, 'rhsa'::text, 'msrc'::text])))
);


--
-- Name: advisory_affects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisory_affects (
    id uuid NOT NULL,
    advisory_id uuid NOT NULL,
    package_name text NOT NULL,
    ecosystem text NOT NULL,
    platform text,
    fixed_version text,
    backported boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_advisory_affects_ecosystem CHECK ((ecosystem = ANY (ARRAY['deb'::text, 'rpm'::text, 'windows'::text])))
);


--
-- Name: asset_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_packages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    epoch integer,
    arch text,
    source text,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.asset_packages FORCE ROW LEVEL SECURITY;


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    hostname text NOT NULL,
    ip text,
    os_family text,
    os_version text,
    managed boolean NOT NULL,
    source text NOT NULL,
    state text NOT NULL,
    last_seen timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.assets FORCE ROW LEVEL SECURITY;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    at timestamp with time zone NOT NULL,
    detail jsonb
);

ALTER TABLE ONLY public.audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: content_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.content_sources (
    id uuid NOT NULL,
    kind text NOT NULL,
    instance text NOT NULL,
    endpoint text,
    enabled boolean NOT NULL,
    last_sync_at timestamp with time zone,
    cursor text,
    last_status text NOT NULL,
    last_error text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_content_sources_kind CHECK ((kind = ANY (ARRAY['nvd'::text, 'kev'::text, 'epss'::text, 'usn'::text, 'rhsa'::text, 'msrc'::text, 'wsusscn2'::text]))),
    CONSTRAINT ck_content_sources_last_status CHECK ((last_status = ANY (ARRAY['ok'::text, 'failed'::text, 'never-run'::text])))
);


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    envelope bytea,
    data_key_id uuid,
    target_scope text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.credentials FORCE ROW LEVEL SECURITY;


--
-- Name: data_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.data_keys (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    wrapped_dek bytea,
    key_id text,
    created_at timestamp with time zone NOT NULL,
    retired_at timestamp with time zone
);

ALTER TABLE ONLY public.data_keys FORCE ROW LEVEL SECURITY;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    advisory_id uuid,
    patch_id uuid,
    state text NOT NULL,
    reversible boolean NOT NULL,
    risk_score double precision,
    risk_explanation jsonb,
    opened_at timestamp with time zone NOT NULL,
    closed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.findings FORCE ROW LEVEL SECURITY;


--
-- Name: operators; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.operators (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    email text NOT NULL,
    role text NOT NULL,
    external_auth_ref text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.operators FORCE ROW LEVEL SECURITY;


--
-- Name: patch_supersedence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_supersedence (
    patch_id uuid NOT NULL,
    superseded_by_patch_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_patch_supersedence_no_self_loop CHECK ((patch_id <> superseded_by_patch_id))
);


--
-- Name: patches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patches (
    id uuid NOT NULL,
    source text NOT NULL,
    vendor_id text NOT NULL,
    title text NOT NULL,
    reversible boolean NOT NULL,
    requires_reboot boolean NOT NULL,
    classification text,
    published_at timestamp with time zone,
    withdrawn_at timestamp with time zone,
    provenance jsonb NOT NULL,
    source_metadata jsonb,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_patches_provenance_non_empty CHECK (((jsonb_typeof(provenance) = 'array'::text) AND (jsonb_array_length(provenance) >= 1))),
    CONSTRAINT ck_patches_source CHECK ((source = ANY (ARRAY['usn'::text, 'rhsa'::text, 'msrc'::text, 'wsusscn2'::text])))
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid NOT NULL,
    name text NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: assets ak_assets_tenant_id_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT ak_assets_tenant_id_id UNIQUE (tenant_id, id);


--
-- Name: data_keys ak_data_keys_tenant_id_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_keys
    ADD CONSTRAINT ak_data_keys_tenant_id_id UNIQUE (tenant_id, id);


--
-- Name: __EFMigrationsHistory pk___ef_migrations_history; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."__EFMigrationsHistory"
    ADD CONSTRAINT pk___ef_migrations_history PRIMARY KEY (migration_id);


--
-- Name: advisories pk_advisories; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories
    ADD CONSTRAINT pk_advisories PRIMARY KEY (id);


--
-- Name: advisory_affects pk_advisory_affects; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affects
    ADD CONSTRAINT pk_advisory_affects PRIMARY KEY (id);


--
-- Name: asset_packages pk_asset_packages; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_packages
    ADD CONSTRAINT pk_asset_packages PRIMARY KEY (id);


--
-- Name: assets pk_assets; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT pk_assets PRIMARY KEY (id);


--
-- Name: audit_log pk_audit_log; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT pk_audit_log PRIMARY KEY (id);


--
-- Name: content_sources pk_content_sources; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_sources
    ADD CONSTRAINT pk_content_sources PRIMARY KEY (id);


--
-- Name: credentials pk_credentials; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT pk_credentials PRIMARY KEY (id);


--
-- Name: data_keys pk_data_keys; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_keys
    ADD CONSTRAINT pk_data_keys PRIMARY KEY (id);


--
-- Name: findings pk_findings; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT pk_findings PRIMARY KEY (id);


--
-- Name: operators pk_operators; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operators
    ADD CONSTRAINT pk_operators PRIMARY KEY (id);


--
-- Name: patch_supersedence pk_patch_supersedence; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_supersedence
    ADD CONSTRAINT pk_patch_supersedence PRIMARY KEY (patch_id, superseded_by_patch_id);


--
-- Name: patches pk_patches; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patches
    ADD CONSTRAINT pk_patches PRIMARY KEY (id);


--
-- Name: tenants pk_tenants; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT pk_tenants PRIMARY KEY (id);


--
-- Name: ix_advisories_source_external_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_advisories_source_external_id ON public.advisories USING btree (source, external_id);


--
-- Name: ix_advisory_affects_advisory_id_package_name_ecosystem_platform; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_advisory_affects_advisory_id_package_name_ecosystem_platform ON public.advisory_affects USING btree (advisory_id, package_name, ecosystem, platform) NULLS NOT DISTINCT;


--
-- Name: ix_advisory_affects_package_name_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_advisory_affects_package_name_ecosystem ON public.advisory_affects USING btree (package_name, ecosystem);


--
-- Name: ix_asset_packages_tenant_id_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_asset_packages_tenant_id_asset_id ON public.asset_packages USING btree (tenant_id, asset_id);


--
-- Name: ix_assets_tenant_id_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_assets_tenant_id_hostname ON public.assets USING btree (tenant_id, hostname);


--
-- Name: ix_audit_log_tenant_id_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_tenant_id_at ON public.audit_log USING btree (tenant_id, at);


--
-- Name: ix_content_sources_kind_instance; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_content_sources_kind_instance ON public.content_sources USING btree (kind, instance);


--
-- Name: ix_credentials_tenant_id_data_key_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_credentials_tenant_id_data_key_id ON public.credentials USING btree (tenant_id, data_key_id);


--
-- Name: ix_findings_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_advisory_id ON public.findings USING btree (advisory_id);


--
-- Name: ix_findings_patch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_patch_id ON public.findings USING btree (patch_id);


--
-- Name: ix_findings_tenant_id_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_tenant_id_asset_id ON public.findings USING btree (tenant_id, asset_id);


--
-- Name: ix_findings_tenant_id_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_tenant_id_state ON public.findings USING btree (tenant_id, state);


--
-- Name: ix_operators_tenant_id_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_operators_tenant_id_email ON public.operators USING btree (tenant_id, email);


--
-- Name: ix_patch_supersedence_superseded_by_patch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_supersedence_superseded_by_patch_id ON public.patch_supersedence USING btree (superseded_by_patch_id);


--
-- Name: ix_patches_source_vendor_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_patches_source_vendor_id ON public.patches USING btree (source, vendor_id);


--
-- Name: advisory_affects fk_advisory_affects_advisories_advisory_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affects
    ADD CONSTRAINT fk_advisory_affects_advisories_advisory_id FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;


--
-- Name: asset_packages fk_asset_packages_assets_tenant_id_asset_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_packages
    ADD CONSTRAINT fk_asset_packages_assets_tenant_id_asset_id FOREIGN KEY (tenant_id, asset_id) REFERENCES public.assets(tenant_id, id) ON DELETE CASCADE;


--
-- Name: asset_packages fk_asset_packages_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_packages
    ADD CONSTRAINT fk_asset_packages_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: assets fk_assets_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT fk_assets_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: audit_log fk_audit_log_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT fk_audit_log_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: credentials fk_credentials_data_keys_tenant_id_data_key_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT fk_credentials_data_keys_tenant_id_data_key_id FOREIGN KEY (tenant_id, data_key_id) REFERENCES public.data_keys(tenant_id, id) ON DELETE RESTRICT;


--
-- Name: credentials fk_credentials_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT fk_credentials_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: data_keys fk_data_keys_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_keys
    ADD CONSTRAINT fk_data_keys_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: findings fk_findings_advisories_advisory_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_advisories_advisory_id FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE RESTRICT;


--
-- Name: findings fk_findings_assets_tenant_id_asset_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_assets_tenant_id_asset_id FOREIGN KEY (tenant_id, asset_id) REFERENCES public.assets(tenant_id, id) ON DELETE RESTRICT;


--
-- Name: findings fk_findings_patches_patch_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_patches_patch_id FOREIGN KEY (patch_id) REFERENCES public.patches(id) ON DELETE RESTRICT;


--
-- Name: findings fk_findings_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: operators fk_operators_tenants_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operators
    ADD CONSTRAINT fk_operators_tenants_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: patch_supersedence fk_patch_supersedence_patches_patch_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_supersedence
    ADD CONSTRAINT fk_patch_supersedence_patches_patch_id FOREIGN KEY (patch_id) REFERENCES public.patches(id) ON DELETE CASCADE;


--
-- Name: patch_supersedence fk_patch_supersedence_patches_superseded_by_patch_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_supersedence
    ADD CONSTRAINT fk_patch_supersedence_patches_superseded_by_patch_id FOREIGN KEY (superseded_by_patch_id) REFERENCES public.patches(id) ON DELETE CASCADE;


--
-- Name: asset_packages; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.asset_packages ENABLE ROW LEVEL SECURITY;

--
-- Name: assets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: data_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.data_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: findings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

--
-- Name: operators; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.operators ENABLE ROW LEVEL SECURITY;

--
-- Name: asset_packages tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.asset_packages USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: assets tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.assets USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: audit_log tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.audit_log USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: credentials tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.credentials USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: data_keys tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.data_keys USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: findings tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.findings USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: operators tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.operators USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA public TO patchmgmt_app;
GRANT USAGE ON SCHEMA public TO patchmgmt_content;


--
-- Name: TABLE advisories; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.advisories TO patchmgmt_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.advisories TO patchmgmt_content;


--
-- Name: TABLE advisory_affects; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.advisory_affects TO patchmgmt_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.advisory_affects TO patchmgmt_content;


--
-- Name: TABLE asset_packages; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.asset_packages TO patchmgmt_app;


--
-- Name: TABLE assets; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.assets TO patchmgmt_app;


--
-- Name: TABLE audit_log; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT ON TABLE public.audit_log TO patchmgmt_app;


--
-- Name: TABLE content_sources; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.content_sources TO patchmgmt_content;


--
-- Name: TABLE credentials; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.credentials TO patchmgmt_app;


--
-- Name: TABLE data_keys; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.data_keys TO patchmgmt_app;


--
-- Name: TABLE findings; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.findings TO patchmgmt_app;


--
-- Name: TABLE operators; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.operators TO patchmgmt_app;


--
-- Name: TABLE patch_supersedence; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.patch_supersedence TO patchmgmt_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.patch_supersedence TO patchmgmt_content;


--
-- Name: TABLE patches; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.patches TO patchmgmt_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.patches TO patchmgmt_content;


--
-- Name: TABLE tenants; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.tenants TO patchmgmt_app;


--
-- PostgreSQL database dump complete
--

\unrestrict aYe6U0sfIj866WgTVImAvgHXN8IwUXwDmGxZKQqJwBH5IwkwIb0v3LhOsJ5BX7I

