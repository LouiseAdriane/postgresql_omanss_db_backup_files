-- =============================================================================
--  OMANSS MANAGEMENT SYSTEM
--  File 3 of 3: Database-Level RBAC — Roles, Privileges, Security Views
--  Run this file AFTER 01_schema_postgresql.sql and 02_seed_data_postgresql.sql.
--  Compatible with: PostgreSQL 13+
-- =============================================================================
--
--  DESIGN OVERVIEW
--  ───────────────
--  This file establishes PostgreSQL database-level RBAC using actual DB roles
--  (CREATE ROLE), which are separate from the application-level `user_account.role`
--  column already in the schema. Both layers work together:
--
--    ┌─────────────────────────────────────────────────────────────────────┐
--    │  APPLICATION LAYER   user_account.role  ('President','Treasurer'…) │
--    │  Controls what the app UI shows and which procedures can be called. │
--    ├─────────────────────────────────────────────────────────────────────┤
--    │  DATABASE LAYER      PostgreSQL roles   (omanss_officer, …)        │
--    │  Controls what SQL operations are physically permitted at the DB.   │
--    └─────────────────────────────────────────────────────────────────────┘
--
--  ROLE HIERARCHY (inheritance shown with →)
--  ─────────────────────────────────────────
--
--   omanss_readonly          Read-only access to non-sensitive tables/views
--        ↑
--   omanss_member            Extends readonly + own attendance/clearance/borrow
--        ↑
--   omanss_officer           Extends member + manage members, sessions, inventory
--        ↑
--   omanss_secretary         Extends officer + documents, announcements
--   omanss_treasurer         Extends officer + full financial write access
--   omanss_auditor           Extends readonly + read ALL financial + audit logs
--   omanss_president         Extends officer + approve liquidations + all reads
--   omanss_admin             Full DDL + DML for system maintenance (no login)
--
--  LOGIN USERS (one per deployment role, all with NOINHERIT for explicit SET ROLE)
--  ───────────────────────────────────────────────────────────────────────────────
--   app_member_user          → used by the app when a Member is logged in
--   app_officer_user         → used by the app when a general Officer is logged in
--   app_secretary_user       → Secretary / Vice-President
--   app_treasurer_user       → Treasurer
--   app_auditor_user         → Auditor
--   app_president_user       → President (also covers VP for most actions)
--   app_admin_user           → System maintainer / DBA
--
--  NOTE: In a real deployment each login user would be given a strong, unique
--  password.  Placeholders are used below — replace before going live.
--
-- =============================================================================



-- =============================================================================
--  SECTION 0 — SAFETY: REVOKE PUBLIC DEFAULTS
--  PostgreSQL grants CONNECT and schema USAGE to PUBLIC by default.
--  Tighten this before granting specific privileges.
-- =============================================================================

-- Prevent any role from connecting unless explicitly granted.
REVOKE CONNECT ON DATABASE omanss_db FROM PUBLIC;

-- Prevent any role from accessing public schema objects unless explicitly granted.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT  USAGE ON SCHEMA public TO PUBLIC;   -- Allow schema visibility only.

-- Strip default table-level grants that PostgreSQL may apply to PUBLIC.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL PROCEDURES IN SCHEMA public FROM PUBLIC;


-- =============================================================================
--  SECTION 1 — CREATE GROUP ROLES  (NOLOGIN = not a login user, just a group)
-- =============================================================================

-- ── Base read-only ─────────────────────────────────────────────────────────
CREATE ROLE omanss_readonly  NOLOGIN NOINHERIT;

-- ── Regular member (inherits readonly) ────────────────────────────────────
CREATE ROLE omanss_member    NOLOGIN NOINHERIT;

-- ── Officer base (inherits member) ────────────────────────────────────────
CREATE ROLE omanss_officer   NOLOGIN NOINHERIT;

-- ── Specialised officer roles (each inherits officer) ─────────────────────
CREATE ROLE omanss_secretary  NOLOGIN NOINHERIT;
CREATE ROLE omanss_treasurer  NOLOGIN NOINHERIT;
CREATE ROLE omanss_auditor    NOLOGIN NOINHERIT;
CREATE ROLE omanss_president  NOLOGIN NOINHERIT;

-- ── System admin (full access, no login — must SET ROLE from app_admin_user)
CREATE ROLE omanss_admin     NOLOGIN NOINHERIT BYPASSRLS;

-- Set up inheritance chain via GRANT ROLE
GRANT omanss_readonly TO omanss_member;
GRANT omanss_member   TO omanss_officer;
GRANT omanss_officer  TO omanss_secretary;
GRANT omanss_officer  TO omanss_treasurer;
GRANT omanss_officer  TO omanss_president;
-- Auditor intentionally does NOT inherit officer — read-only + financial view only.
GRANT omanss_readonly TO omanss_auditor;


-- =============================================================================
--  SECTION 2 — CREATE LOGIN USERS  (NOINHERIT so they must SET ROLE explicitly)
-- =============================================================================

-- Replace '<strong_password_N>' with secure passwords before deployment.

CREATE ROLE app_member_user    LOGIN NOINHERIT PASSWORD '<strong_password_1>'
    CONNECTION LIMIT 100;

CREATE ROLE app_officer_user   LOGIN NOINHERIT PASSWORD '<strong_password_2>'
    CONNECTION LIMIT 50;

CREATE ROLE app_secretary_user LOGIN NOINHERIT PASSWORD '<strong_password_3>'
    CONNECTION LIMIT 20;

CREATE ROLE app_treasurer_user LOGIN NOINHERIT PASSWORD '<strong_password_4>'
    CONNECTION LIMIT 20;

CREATE ROLE app_auditor_user   LOGIN NOINHERIT PASSWORD '<strong_password_5>'
    CONNECTION LIMIT 10;

CREATE ROLE app_president_user LOGIN NOINHERIT PASSWORD '<strong_password_6>'
    CONNECTION LIMIT 10;

CREATE ROLE app_admin_user     LOGIN NOINHERIT PASSWORD '<strong_password_7>'
    CONNECTION LIMIT 5;

-- Grant DB connect to each login user.
GRANT CONNECT ON DATABASE omanss_db TO
    app_member_user,
    app_officer_user,
    app_secretary_user,
    app_treasurer_user,
    app_auditor_user,
    app_president_user,
    app_admin_user;

-- Map login users → group roles.
GRANT omanss_member    TO app_member_user;
GRANT omanss_officer   TO app_officer_user;
GRANT omanss_secretary TO app_secretary_user;
GRANT omanss_treasurer TO app_treasurer_user;
GRANT omanss_auditor   TO app_auditor_user;
GRANT omanss_president TO app_president_user;
GRANT omanss_admin     TO app_admin_user;


-- =============================================================================
--  SECTION 3 — GRANT CONNECT / SCHEMA USAGE TO ALL LOGIN USERS
-- =============================================================================

GRANT USAGE ON SCHEMA public TO
    omanss_readonly,
    omanss_member,
    omanss_officer,
    omanss_secretary,
    omanss_treasurer,
    omanss_auditor,
    omanss_president,
    omanss_admin;


-- =============================================================================
--  SECTION 4 — omanss_readonly PRIVILEGES
--  Can SELECT non-sensitive, non-financial, non-audit tables and public views.
-- =============================================================================

-- Public-facing / non-sensitive tables
GRANT SELECT ON
    member,
    officer_role,
    attendance_session,
    attendance_record,
    announcement,
    inventory_item,
    borrow_transaction,
    document,
    clearance,
    budget_proposal
TO omanss_readonly;

-- Public views (exclude financial detail view and audit view)
GRANT SELECT ON
    vw_member_summary,
    vw_attendance_summary,
    vw_inventory_status,
    vw_overdue_items,
    vw_unpaid_members
TO omanss_readonly;

-- Read-only scalar functions are safe for everyone.
GRANT EXECUTE ON FUNCTION
    fn_get_member_balance(INT),
    fn_has_unreturned_items(INT),
    fn_count_absences(INT),
    fn_get_attendance_rate(INT)
TO omanss_readonly;


-- =============================================================================
--  SECTION 5 — omanss_member PRIVILEGES  (on top of readonly via inheritance)
--  Members can view their own data and submit feedback/document requests.
--  NOTE: Row-level restrictions on sensitive columns are enforced via
--  the security views defined in Section 10 below.
-- =============================================================================

-- Members submit feedback anonymously or attributed.
GRANT INSERT ON feedback TO omanss_member;
GRANT USAGE, SELECT ON SEQUENCE feedback_feedback_id_seq TO omanss_member;

-- Members can view their own feedback (full table select here;
-- use vw_member_feedback view from Section 10 to restrict rows in the app).
GRANT SELECT ON feedback TO omanss_member;

-- Members request documents (INSERT only; status changes done by officer).
GRANT INSERT ON document TO omanss_member;
GRANT USAGE, SELECT ON SEQUENCE document_doc_id_seq TO omanss_member;

-- Members view their own document requests (row-filtering via app query / view).
GRANT SELECT ON document TO omanss_member;

-- Procedures members are permitted to CALL:
GRANT EXECUTE ON PROCEDURE sp_register_member(
    VARCHAR, VARCHAR, VARCHAR, VARCHAR, SMALLINT, VARCHAR, DATE,
    VARCHAR, VARCHAR, VARCHAR, INT, VARCHAR
) TO omanss_member;
-- Note: sp_register_member is also used by admin/officer during onboarding.


-- =============================================================================
--  SECTION 6 — omanss_officer PRIVILEGES  (on top of member via inheritance)
--  Officers manage day-to-day operations: members, attendance, inventory.
-- =============================================================================

-- Member management
GRANT INSERT, UPDATE ON member    TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE member_member_id_seq TO omanss_officer;

-- User account management (officers can create/activate accounts)
GRANT SELECT, INSERT, UPDATE ON user_account TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE user_account_account_id_seq TO omanss_officer;

-- Attendance
GRANT INSERT, UPDATE ON attendance_session TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE attendance_session_session_id_seq TO omanss_officer;
GRANT INSERT, UPDATE ON attendance_record  TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE attendance_record_record_id_seq TO omanss_officer;

-- Inventory management
GRANT INSERT, UPDATE ON inventory_item     TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE inventory_item_item_id_seq TO omanss_officer;
GRANT INSERT, UPDATE ON borrow_transaction TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE borrow_transaction_tx_id_seq TO omanss_officer;

-- Fines (officers can record fines, but NOT full financial tables — see treasurer)
GRANT INSERT ON finance_transaction TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE finance_transaction_tx_id_seq TO omanss_officer;
GRANT SELECT ON finance_transaction TO omanss_officer;

-- Clearance evaluation
GRANT INSERT, UPDATE ON clearance TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE clearance_clearance_id_seq TO omanss_officer;

-- Officer roles table (read — only admin/president should write this)
GRANT SELECT ON officer_role TO omanss_officer;

-- Audit log (INSERT only — officers must not UPDATE or DELETE audit records)
GRANT INSERT ON audit_log TO omanss_officer;
GRANT USAGE, SELECT ON SEQUENCE audit_log_log_id_seq TO omanss_officer;

-- Login attempt (officers can view for account support)
GRANT SELECT ON login_attempt TO omanss_officer;

-- SP 1: sp_register_member (also callable by officer and above)
-- Signature: (p_student_id, p_first_name, p_last_name, p_course, p_year_level,
--             p_membership_type, p_date_enrolled, p_username, p_password_hash,
--             p_role, OUT p_new_member_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_register_member(
    VARCHAR, VARCHAR, VARCHAR, VARCHAR, SMALLINT, VARCHAR, DATE,
    VARCHAR, VARCHAR, VARCHAR, INT, VARCHAR
) TO omanss_officer;

-- Procedures officers can call:
-- SP 1 — already granted to omanss_member; inherited here via role chain.
-- SP 2: sp_update_member_status(p_member_id, p_new_status, p_grounds, p_account_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_update_member_status(INT, VARCHAR, TEXT, INT, VARCHAR)
    TO omanss_officer;
-- SP 7: sp_open_attendance_session(p_session_name, p_session_type, p_session_date, p_created_by, p_account_id, OUT p_session_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_open_attendance_session(VARCHAR, VARCHAR, DATE, INT, INT, INT, VARCHAR)
    TO omanss_officer;
-- SP 8: sp_record_attendance(p_session_id, p_member_id, p_status, p_remarks, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_record_attendance(INT, INT, VARCHAR, TEXT, VARCHAR)
    TO omanss_officer;
-- SP 9: sp_record_borrow(p_item_id, p_member_id, p_tx_type, p_borrow_date, p_expected_return, p_account_id, OUT p_tx_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_record_borrow(INT, INT, VARCHAR, DATE, DATE, INT, INT, VARCHAR)
    TO omanss_officer;
-- SP 10: sp_record_return(p_tx_id, p_return_date, p_condition, p_account_id, OUT p_penalty, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_record_return(INT, DATE, VARCHAR, INT, NUMERIC, VARCHAR)
    TO omanss_officer;
-- SP 11: sp_evaluate_clearance(p_member_id, p_term, p_account_id, OUT p_status, OUT p_reasons, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_evaluate_clearance(INT, VARCHAR, INT, VARCHAR, TEXT, VARCHAR)
    TO omanss_officer;


-- =============================================================================
--  SECTION 7 — omanss_secretary PRIVILEGES  (on top of officer via inheritance)
--  Secretary manages documents and announcements.
-- =============================================================================

-- Full document lifecycle management
GRANT INSERT, UPDATE, DELETE ON document TO omanss_secretary;
-- (SELECT already inherited from readonly; sequences inherited from member)

-- Announcement management
GRANT INSERT, UPDATE ON announcement TO omanss_secretary;
GRANT USAGE, SELECT ON SEQUENCE announcement_announcement_id_seq TO omanss_secretary;

-- Secretary can update officer_role table (term tracking)
GRANT INSERT, UPDATE ON officer_role TO omanss_secretary;
GRANT USAGE, SELECT ON SEQUENCE officer_role_role_id_seq TO omanss_secretary;

-- Procedures secretary can call:
-- SP 12: sp_post_announcement(p_posted_by, p_title, p_content, p_target_audience, p_account_id, OUT p_announcement_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_post_announcement(INT, VARCHAR, TEXT, VARCHAR, INT, INT, VARCHAR)
    TO omanss_secretary;
-- Secretary also inherits sp_update_member_status, sp_open_attendance_session,
-- sp_record_attendance, sp_record_borrow, sp_record_return, sp_evaluate_clearance
-- from omanss_officer via the role chain.


-- =============================================================================
--  SECTION 8 — omanss_treasurer PRIVILEGES  (on top of officer via inheritance)
--  Treasurer owns all financial write operations.
-- =============================================================================

-- Full financial table access
GRANT INSERT, UPDATE ON finance_transaction  TO omanss_treasurer;
GRANT INSERT, UPDATE ON budget_proposal      TO omanss_treasurer;
GRANT USAGE, SELECT ON SEQUENCE budget_proposal_proposal_id_seq  TO omanss_treasurer;
GRANT INSERT, UPDATE ON liquidation_package  TO omanss_treasurer;
GRANT USAGE, SELECT ON SEQUENCE liquidation_package_package_id_seq TO omanss_treasurer;
GRANT INSERT, UPDATE ON disbursement         TO omanss_treasurer;
GRANT USAGE, SELECT ON SEQUENCE disbursement_disbursement_id_seq TO omanss_treasurer;

-- Financial summary views
GRANT SELECT ON vw_financial_summary    TO omanss_treasurer;
GRANT SELECT ON vw_liquidation_status   TO omanss_treasurer;
GRANT SELECT ON vw_unpaid_members       TO omanss_treasurer;

-- Procedures treasurer can call:
-- SP 3: sp_record_payment(p_member_id, p_tx_type, p_amount, p_fee_type, p_reference_no, p_recorder_id, OUT p_tx_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_record_payment(INT, VARCHAR, NUMERIC, VARCHAR, VARCHAR, INT, INT, VARCHAR)
    TO omanss_treasurer;
-- SP 4: sp_record_disbursement(p_proposal_id, p_purpose, p_amount, p_payee, p_or_ar_ref, p_dv_number, p_account_id, OUT p_dis_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_record_disbursement(INT, TEXT, NUMERIC, VARCHAR, VARCHAR, VARCHAR, INT, INT, VARCHAR)
    TO omanss_treasurer;
-- SP 5: sp_prepare_liquidation_package(p_proposal_id, p_lr_number, p_crf_number, p_rf_number, p_account_id, OUT p_package_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_prepare_liquidation_package(INT, VARCHAR, VARCHAR, VARCHAR, INT, INT, VARCHAR)
    TO omanss_treasurer;
-- NOTE: No sp_create_budget_proposal exists in the schema — budget_proposal rows are
--       inserted directly. The treasurer role has INSERT on budget_proposal above.
-- NOTE: Treasurer deliberately CANNOT approve liquidations.
--       sp_approve_liquidation is reserved for omanss_president only.


-- =============================================================================
--  SECTION 9 — omanss_auditor PRIVILEGES
--  Auditor has broad read access including financial and audit tables,
--  but NO write access anywhere.  Inherits only omanss_readonly.
-- =============================================================================

-- Financial read access (denied to regular readonly role)
GRANT SELECT ON finance_transaction  TO omanss_auditor;
GRANT SELECT ON budget_proposal      TO omanss_auditor;
GRANT SELECT ON liquidation_package  TO omanss_auditor;
GRANT SELECT ON disbursement         TO omanss_auditor;

-- Audit log read access (highly sensitive — auditor-only)
GRANT SELECT ON audit_log            TO omanss_auditor;
GRANT SELECT ON login_attempt        TO omanss_auditor;
GRANT SELECT ON user_account         TO omanss_auditor;

-- Auditor-relevant views
GRANT SELECT ON vw_financial_summary  TO omanss_auditor;
GRANT SELECT ON vw_liquidation_status TO omanss_auditor;
GRANT SELECT ON vw_audit_recent       TO omanss_auditor;
GRANT SELECT ON vw_unpaid_members     TO omanss_auditor;

-- Auditor inserts to audit log only (to record their own review actions)
GRANT INSERT ON audit_log TO omanss_auditor;
GRANT USAGE, SELECT ON SEQUENCE audit_log_log_id_seq TO omanss_auditor;


-- =============================================================================
--  SECTION 10 — omanss_president PRIVILEGES  (on top of officer via inheritance)
--  President has broad read access + final approval authority.
-- =============================================================================

-- Financial reads (president approves liquidations, must see full picture)
GRANT SELECT ON finance_transaction  TO omanss_president;
GRANT SELECT ON budget_proposal      TO omanss_president;
GRANT SELECT ON liquidation_package  TO omanss_president;
GRANT SELECT ON disbursement         TO omanss_president;

-- Audit log read (president oversees all operations)
GRANT SELECT ON audit_log            TO omanss_president;
GRANT SELECT ON login_attempt        TO omanss_president;
GRANT SELECT ON user_account         TO omanss_president;

-- Financial views
GRANT SELECT ON vw_financial_summary  TO omanss_president;
GRANT SELECT ON vw_liquidation_status TO omanss_president;
GRANT SELECT ON vw_audit_recent       TO omanss_president;

-- Officer role management (president appoints officers)
GRANT INSERT, UPDATE ON officer_role TO omanss_president;
GRANT USAGE, SELECT ON SEQUENCE officer_role_role_id_seq TO omanss_president;

-- Announcement management (president can post announcements directly)
GRANT INSERT, UPDATE ON announcement TO omanss_president;
GRANT USAGE, SELECT ON SEQUENCE announcement_announcement_id_seq TO omanss_president;

-- Procedures president can call:
-- SP 6: sp_approve_liquidation(p_package_id, p_adviser_id, p_decision, p_remarks, p_account_id, OUT p_message)
GRANT EXECUTE ON PROCEDURE sp_approve_liquidation(INT, INT, VARCHAR, TEXT, INT, VARCHAR)
    TO omanss_president;
-- SP 12: sp_post_announcement
GRANT EXECUTE ON PROCEDURE sp_post_announcement(INT, VARCHAR, TEXT, VARCHAR, INT, INT, VARCHAR)
    TO omanss_president;
-- SP 2: sp_update_member_status (also inherited from omanss_officer)
GRANT EXECUTE ON PROCEDURE sp_update_member_status(INT, VARCHAR, TEXT, INT, VARCHAR)
    TO omanss_president;
-- President also inherits all officer-level procedures via the role chain.


-- =============================================================================
--  SECTION 11 — omanss_admin PRIVILEGES
--  Full access for system maintenance.  Login is app_admin_user which must
--  SET ROLE omanss_admin to activate elevated privileges.
-- =============================================================================

-- Admin owns the schema and all objects.
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO omanss_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO omanss_admin;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO omanss_admin;
GRANT ALL PRIVILEGES ON ALL PROCEDURES IN SCHEMA public TO omanss_admin;

-- Allow admin to manage roles (needed for user account maintenance).
-- Note: CREATEROLE and CREATEDB must be granted at the cluster level by a superuser.
-- ALTER ROLE app_admin_user CREATEROLE;  -- Uncomment only if needed.


-- =============================================================================
--  SECTION 12 — SECURITY VIEWS FOR ROW-LEVEL ISOLATION
--  These views restrict what each role sees without changing the base tables.
--  Grant SELECT on these views in addition to (or instead of) base table access.
-- =============================================================================

-- ── VIEW: vw_member_own_attendance ───────────────────────────────────────────
--  Used by the app when a Member queries their own attendance.
--  The application passes current_setting('app.current_member_id') at login.
CREATE OR REPLACE VIEW vw_member_own_attendance AS
SELECT
    ar.record_id,
    s.session_name,
    s.session_date,
    s.session_type,
    ar.status,
    ar.remarks,
    ar.recorded_at
FROM attendance_record ar
JOIN attendance_session s ON ar.session_id = s.session_id
WHERE ar.member_id = NULLIF(current_setting('app.current_member_id', TRUE), '')::INT;

GRANT SELECT ON vw_member_own_attendance TO omanss_member;

-- ── VIEW: vw_member_own_fines ────────────────────────────────────────────────
--  Members can only see their own financial transactions (fines/fees).
--  Prevents cross-member financial snooping.
CREATE OR REPLACE VIEW vw_member_own_fines AS
SELECT
    tx_id,
    tx_type,
    amount,
    fee_type,
    reference_no,
    recorded_at
FROM finance_transaction
WHERE member_id = NULLIF(current_setting('app.current_member_id', TRUE), '')::INT
  AND tx_type IN ('Fine', 'Fee', 'Payment');

GRANT SELECT ON vw_member_own_fines TO omanss_member;

-- ── VIEW: vw_member_own_documents ────────────────────────────────────────────
CREATE OR REPLACE VIEW vw_member_own_documents AS
SELECT
    doc_id,
    doc_type,
    file_reference,
    status,
    created_at
FROM document
WHERE request_by = NULLIF(current_setting('app.current_member_id', TRUE), '')::INT;

GRANT SELECT ON vw_member_own_documents TO omanss_member;

-- ── VIEW: vw_member_own_borrows ──────────────────────────────────────────────
CREATE OR REPLACE VIEW vw_member_own_borrows AS
SELECT
    bt.tx_id,
    ii.item_name,
    ii.category,
    bt.tx_type,
    bt.borrow_date,
    bt.expected_return,
    bt.actual_return,
    bt.cond_status,
    bt.penalty_amount
FROM borrow_transaction bt
JOIN inventory_item ii ON bt.item_id = ii.item_id
WHERE bt.member_id = NULLIF(current_setting('app.current_member_id', TRUE), '')::INT;

GRANT SELECT ON vw_member_own_borrows TO omanss_member;

-- ── VIEW: vw_member_own_clearance ────────────────────────────────────────────
CREATE OR REPLACE VIEW vw_member_own_clearance AS
SELECT
    clearance_id,
    term,
    status,
    blocking_reasons,
    evaluated_at
FROM clearance
WHERE member_id = NULLIF(current_setting('app.current_member_id', TRUE), '')::INT;

GRANT SELECT ON vw_member_own_clearance TO omanss_member;

-- ── VIEW: vw_safe_member_list ────────────────────────────────────────────────
--  Strips password_hash from user_account before officers can view it.
CREATE OR REPLACE VIEW vw_safe_user_accounts AS
SELECT
    account_id,
    member_id,
    username,
    role,
    is_active,
    created_at
FROM user_account;
-- password_hash is intentionally excluded.

GRANT SELECT ON vw_safe_user_accounts TO omanss_officer;
GRANT SELECT ON vw_safe_user_accounts TO omanss_auditor;
GRANT SELECT ON vw_safe_user_accounts TO omanss_president;

-- ── REVOKE direct SELECT on user_account from officer (they should use the view)
REVOKE SELECT ON user_account FROM omanss_officer;


-- =============================================================================
--  SECTION 13 — EXPLICIT DENIALS (REVOKE) FOR SENSITIVE OPERATIONS
--  Belt-and-suspenders: explicitly revoke things that should never be granted.
-- =============================================================================

-- Nobody except admin should be able to DELETE audit logs or login attempts.
REVOKE DELETE ON audit_log     FROM omanss_officer, omanss_secretary,
                                    omanss_treasurer, omanss_president, omanss_auditor;
REVOKE DELETE ON login_attempt FROM omanss_officer, omanss_secretary,
                                    omanss_treasurer, omanss_president, omanss_auditor;

-- Nobody except admin should UPDATE audit logs (append-only ledger).
REVOKE UPDATE ON audit_log FROM omanss_officer, omanss_secretary,
                                omanss_treasurer, omanss_president, omanss_auditor;

-- Members must never directly read other members' financial transactions.
REVOKE SELECT ON finance_transaction FROM omanss_member;
-- Members read their own data through vw_member_own_fines instead.

-- Members must never see full user_account table (passwords).
REVOKE SELECT ON user_account FROM omanss_member;

-- Officers must never DELETE members, finance records, or audit logs
-- (all deletes go through admin or are handled by ON DELETE constraints).
REVOKE DELETE ON member             FROM omanss_officer;
REVOKE DELETE ON finance_transaction FROM omanss_officer;

-- Treasurer must not delete financial records (append-only accounting).
REVOKE DELETE ON finance_transaction FROM omanss_treasurer;
REVOKE DELETE ON disbursement        FROM omanss_treasurer;
REVOKE DELETE ON liquidation_package FROM omanss_treasurer;


-- =============================================================================
--  SECTION 14 — DEFAULT PRIVILEGES FOR FUTURE OBJECTS
--  Ensures new tables/views/functions created later inherit the same grants.
-- =============================================================================

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO omanss_readonly;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO omanss_readonly;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON TABLES    TO omanss_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON SEQUENCES TO omanss_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON FUNCTIONS TO omanss_admin;


-- =============================================================================
--  SECTION 15 — HOW TO USE: SET ROLE IN YOUR APPLICATION
-- =============================================================================
--
--  Because all login users are created with NOINHERIT, the application must
--  explicitly activate the group role after connecting. Example pattern:
--
--    -- At login, after authenticating via user_account table:
--    SET LOCAL ROLE omanss_member;     -- for a regular member session
--    SET LOCAL ROLE omanss_treasurer;  -- for a treasurer session
--    SET LOCAL ROLE omanss_president;  -- for a president session
--
--  Additionally, for the row-level security views to work, the app sets:
--
--    SET LOCAL app.current_member_id = '<member_id>';
--
--  Example in psycopg2 (Python):
--
--    with conn.cursor() as cur:
--        cur.execute("SET LOCAL ROLE omanss_member")
--        cur.execute("SET LOCAL app.current_member_id = %s", (member_id,))
--        cur.execute("SELECT * FROM vw_member_own_fines")
--
-- =============================================================================


-- =============================================================================
--  SECTION 16 — ROLE-PERMISSION REFERENCE MATRIX
-- =============================================================================
--
--  Legend:  S=SELECT  I=INSERT  U=UPDATE  D=DELETE  X=EXECUTE  -=No access
--  (✓ = via inherited role)
--
--  TABLE / PROCEDURE               | readonly | member | officer | secretary | treasurer | auditor | president | admin
--  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--  member                          |    S     |   ✓S   |  SIU    |    ✓SIU   |   ✓SIU    |   ✓S    |  ✓SIUD?   |  ALL
--  user_account (raw)              |    -     |    -   |  SIU*   |   ✓SIU*   |     -     |    S    |    S      |  ALL
--  vw_safe_user_accounts           |    -     |    -   |   S     |    ✓S     |     -     |    S    |    S      |  (view)
--  login_attempt                   |    -     |    -   |   S     |    ✓S     |     -     |    S    |    S      |  ALL
--  officer_role                    |    S     |   ✓S   |   ✓S    |   SIUD?   |   ✓S      |   ✓S    |   SIU     |  ALL
--  attendance_session              |    S     |   ✓S   |  SIU    |   ✓SIU    |   ✓SIU    |   ✓S    |  ✓SIU     |  ALL
--  attendance_record               |    S     |   ✓S   |  SIU    |   ✓SIU    |   ✓SIU    |   ✓S    |  ✓SIU     |  ALL
--  announcement                    |    S     |   ✓S   |  ✓S     |   SIU     |   ✓S      |   ✓S    |   SIU     |  ALL
--  feedback                        |    -     |   SI   |   ✓SI   |   ✓SI     |   ✓SI     |    -    |    -      |  ALL
--  finance_transaction             |    -     |    -   |   SI    |    -      |   SIUD-   |    S    |    S      |  ALL
--  budget_proposal                 |    S     |   ✓S   |  ✓S     |   ✓S      |   SIU     |    S    |    S      |  ALL
--  liquidation_package             |    -     |    -   |   -     |    -      |   SIU     |    S    |    S      |  ALL
--  disbursement                    |    -     |    -   |   -     |    -      |   SIU     |    S    |    S      |  ALL
--  document                        |    -     |   SI   |  ✓SI    |   SIUD    |    -      |    -    |    -      |  ALL
--  inventory_item                  |    S     |   ✓S   |  SIU    |   ✓SIU    |   ✓SIU    |   ✓S    |  ✓SIU     |  ALL
--  borrow_transaction              |    S     |   ✓S   |  SIU    |   ✓SIU    |   ✓SIU    |   ✓S    |  ✓SIU     |  ALL
--  clearance                       |    -     |    -   |  SIU    |   ✓SIU    |   ✓SIU    |   ✓S    |  ✓SIU     |  ALL
--  audit_log                       |    -     |    -   |   SI    |   ✓SI     |   ✓SI     |   SI    |   SI      |  ALL
--  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--  vw_member_own_attendance        |    -     |   S    |    -    |    -      |    -      |    -    |    -      |  -
--  vw_member_own_fines             |    -     |   S    |    -    |    -      |    -      |    -    |    -      |  -
--  vw_member_own_documents         |    -     |   S    |    -    |    -      |    -      |    -    |    -      |  -
--  vw_member_own_borrows           |    -     |   S    |    -    |    -      |    -      |    -    |    -      |  -
--  vw_member_own_clearance         |    -     |   S    |    -    |    -      |    -      |    -    |    -      |  -
--  vw_financial_summary            |    -     |    -   |   -     |    -      |    S      |    S    |    S      |  -
--  vw_liquidation_status           |    -     |    -   |   -     |    -      |    S      |    S    |    S      |  -
--  vw_audit_recent                 |    -     |    -   |   -     |    -      |    -      |    S    |    S      |  -
--  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--  sp_register_member              |    -     |   X    |   ✓X    |   ✓X      |   ✓X      |    -    |   ✓X      |  ALL
--  sp_update_member_status         |    -     |    -   |   X     |   ✓X      |    -      |    -    |    X      |  ALL
--  sp_record_payment               |    -     |    -   |   -     |    -      |    X      |    -    |    -      |  ALL
--  sp_record_disbursement          |    -     |    -   |   -     |    -      |    X      |    -    |    -      |  ALL
--  sp_prepare_liquidation_package  |    -     |    -   |   -     |    -      |    X      |    -    |    -      |  ALL
--  sp_approve_liquidation          |    -     |    -   |   -     |    -      |    -      |    -    |    X      |  ALL
--  sp_open_attendance_session      |    -     |    -   |   X     |   ✓X      |    -      |    -    |   ✓X      |  ALL
--  sp_record_attendance            |    -     |    -   |   X     |   ✓X      |    -      |    -    |   ✓X      |  ALL
--  sp_record_borrow                |    -     |    -   |   X     |   ✓X      |    -      |    -    |   ✓X      |  ALL
--  sp_record_return                |    -     |    -   |   X     |   ✓X      |    -      |    -    |   ✓X      |  ALL
--  sp_evaluate_clearance           |    -     |    -   |   X     |   ✓X      |    -      |    -    |   ✓X      |  ALL
--  sp_post_announcement            |    -     |    -   |   -     |    X      |    -      |    -    |    X      |  ALL
--  fn_* (read-only functions)      |    X     |   ✓X   |  ✓X     |   ✓X      |   ✓X      |   ✓X    |  ✓X       |  ALL
--
--  * officer reads user_account only through vw_safe_user_accounts (no password_hash)
--
-- =============================================================================


SELECT '03_rbac_postgresql.sql applied successfully.' AS status;
