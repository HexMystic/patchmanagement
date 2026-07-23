--
-- PostgreSQL database dump
--

\restrict wdbKgfIglNdRlec1YGC93yMS9WKcVfv3m3n7kkKthcs4ilmQ0u0vgGlyyfLeW67

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
-- Name: __EFMigrationsHistory pk___ef_migrations_history; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."__EFMigrationsHistory"
    ADD CONSTRAINT pk___ef_migrations_history PRIMARY KEY (migration_id);


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
-- Name: tenants pk_tenants; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT pk_tenants PRIMARY KEY (id);


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
-- Name: TABLE tenants; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.tenants TO patchmgmt_app;


--
-- PostgreSQL database dump complete
--

\unrestrict wdbKgfIglNdRlec1YGC93yMS9WKcVfv3m3n7kkKthcs4ilmQ0u0vgGlyyfLeW67

