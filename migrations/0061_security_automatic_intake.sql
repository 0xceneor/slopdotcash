-- Automatic private report intake, AI case analysis and discretionary awards
-- (PRD section 8 "Report and decide privately", section 10 Intake, Capacity
-- and Amounts; MVP-13; issue #910).
--
-- Receipt: Slop reads the program repository's GitHub private vulnerability
-- reports and records each one under the GitHub account that GitHub says
-- submitted it, at GitHub's own creation time. Older receipts keep their
-- maintainer-attested time. `verified_by_github_id = 'github'` marks a
-- receipt that Slop verified from GitHub rather than a person.
ALTER TABLE security_cases ADD COLUMN received_at_source TEXT NOT NULL
  DEFAULT 'maintainer-attested'
  CHECK (received_at_source IN ('maintainer-attested', 'github-advisory'));

-- The gross award the owner chose. It is reserved when the award is approved
-- (or when an independent reviewer approves a related-party award). Older
-- awards keep the program amount frozen in `terms`; NULL means none chosen.
ALTER TABLE security_cases ADD COLUMN award_gross_minor TEXT CHECK (
  award_gross_minor IS NULL OR (
    length(award_gross_minor) BETWEEN 1 AND 16 AND
    award_gross_minor GLOB '[1-9]*' AND award_gross_minor NOT GLOB '*[^0-9]*'
  )
);

CREATE TRIGGER security_cases_frozen_receipt_source
BEFORE UPDATE ON security_cases
WHEN OLD.submission_state = 'verified' AND
  NEW.received_at_source IS NOT OLD.received_at_source
BEGIN
  SELECT RAISE(ABORT, 'a verified receipt is immutable');
END;

-- A chosen amount never changes once its reservation exists.
CREATE TRIGGER security_cases_award_amount_fixed
BEFORE UPDATE ON security_cases
WHEN OLD.award_gross_minor IS NOT NULL AND
  NEW.award_gross_minor IS NOT OLD.award_gross_minor AND
  EXISTS (SELECT 1 FROM security_award_reservations WHERE case_id = OLD.id)
BEGIN
  SELECT RAISE(ABORT, 'a reserved award amount is immutable');
END;

-- A signed-in reporter's private report session. It records who started a
-- report on which project and when; it never holds report content. Slop
-- reconciles it against GitHub before the reporter submits again, so an
-- interrupted submission is found instead of duplicated.
CREATE TABLE security_submissions (
  id TEXT PRIMARY KEY CHECK (id GLOB 'ss_*' AND length(id) BETWEEN 12 AND 80),
  project_id TEXT NOT NULL REFERENCES projects(id),
  repository TEXT NOT NULL CHECK (length(repository) BETWEEN 3 AND 201),
  reporter_github_id TEXT NOT NULL CHECK (reporter_github_id GLOB '[1-9]*'),
  reporter_github_login TEXT NOT NULL,
  started_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('awaiting-report', 'received')),
  -- The last reconciliation against GitHub. `unavailable` means Slop could
  -- not read GitHub; it never means that no report exists.
  last_check TEXT CHECK (last_check IS NULL OR last_check IN ('none-found', 'unavailable', 'received')),
  last_checked_at TEXT,
  case_id TEXT REFERENCES security_cases(id),
  updated_at TEXT NOT NULL,
  CHECK ((state = 'received') = (case_id IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX security_submissions_one_open
  ON security_submissions(project_id, reporter_github_id)
  WHERE state = 'awaiting-report';
CREATE INDEX security_submissions_reporter
  ON security_submissions(reporter_github_id, started_at);

CREATE TRIGGER security_submissions_no_delete
BEFORE DELETE ON security_submissions
BEGIN
  SELECT RAISE(ABORT, 'security submissions are permanent');
END;

-- Automatic private analysis of a verified report. It stores only the model's
-- proposal and the digest of the advisory text it read, never the report.
-- A proposal never decides a case or an award.
CREATE TABLE security_case_analyses (
  case_id TEXT NOT NULL REFERENCES security_cases(id),
  attempt INTEGER NOT NULL CHECK (attempt > 0),
  state TEXT NOT NULL CHECK (state IN ('running', 'complete', 'failed', 'unavailable')),
  prompt_revision TEXT NOT NULL,
  provider TEXT,
  model TEXT,
  advisory_digest TEXT CHECK (advisory_digest IS NULL OR length(advisory_digest) = 64),
  summary TEXT CHECK (summary IS NULL OR length(summary) BETWEEN 1 AND 4000),
  proposed_severity TEXT CHECK (proposed_severity IS NULL OR proposed_severity IN (
    'critical', 'high', 'medium', 'low', 'informational', 'unresolved'
  )),
  potential_loss TEXT CHECK (potential_loss IS NULL OR potential_loss IN ('likely', 'unlikely', 'unclear')),
  duplicate_case_ids TEXT CHECK (duplicate_case_ids IS NULL OR json_valid(duplicate_case_ids)),
  root_cause_key TEXT CHECK (root_cause_key IS NULL OR length(root_cause_key) BETWEEN 3 AND 80),
  remediation TEXT CHECK (remediation IS NULL OR length(remediation) BETWEEN 1 AND 4000),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  PRIMARY KEY (case_id, attempt),
  CHECK ((state = 'complete') = (summary IS NOT NULL AND finished_at IS NOT NULL))
) STRICT;

CREATE TRIGGER security_case_analyses_no_delete
BEFORE DELETE ON security_case_analyses
BEGIN
  SELECT RAISE(ABORT, 'security case analyses are permanent');
END;

-- Only a running attempt may finish, once.
CREATE TRIGGER security_case_analyses_finish_once
BEFORE UPDATE ON security_case_analyses
WHEN OLD.state <> 'running' OR NEW.case_id IS NOT OLD.case_id OR
  NEW.attempt IS NOT OLD.attempt OR NEW.started_at IS NOT OLD.started_at
BEGIN
  SELECT RAISE(ABORT, 'a finished analysis is immutable');
END;
