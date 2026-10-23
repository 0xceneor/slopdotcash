// GitHub private report parsing and the read-only advisory reader, against
// recorded-shape responses from a fake GitHub API. No network is used.
import { describe, expect, test } from "bun:test";
import { githubAdvisoryReader, parsePrivateReport } from "./advisories";
import { parseAnalysisProposal } from "./analysis";

const API = "https://api.github.invalid";

function advisory(overrides: Record<string, unknown> = {}) {
  return {
    ghsa_id: "GHSA-7c8f-9g2h-3j4m",
    created_at: "2026-10-19T09:10:00Z",
    state: "triage",
    summary: "Vault share rounding",
    description: "Steps to reproduce on a local fork.",
    severity: "critical",
    cwe_ids: ["CWE-682"],
    vulnerabilities: [{ package: { ecosystem: "npm", name: "vault" } }],
    submission: { accepted: false },
    author: { id: 900000102, login: "reporter", type: "User" },
    ...overrides,
  };
}

describe("GitHub private reports", () => {
  test("only a private report with a known human author is a receipt", () => {
    expect(parsePrivateReport(advisory())).toEqual({
      ghsa: "GHSA-7c8f-9g2h-3j4m",
      createdAt: "2026-10-19T09:10:00.000Z",
      state: "triage",
      author: { githubId: "900000102", githubLogin: "reporter" },
      summary: "Vault share rounding",
      description: "Steps to reproduce on a local fork.",
      severity: "critical",
      cweIds: ["CWE-682"],
      packages: ["npm:vault"],
    });
    // A maintainer-created draft is not a private vulnerability report.
    expect(parsePrivateReport(advisory({ submission: null }))).toBeNull();
    // A deleted account or a bot cannot be bound to a reporter.
    expect(parsePrivateReport(advisory({ author: null }))).toBeNull();
    expect(
      parsePrivateReport(
        advisory({ author: { id: 1, login: "app[bot]", type: "Bot" } }),
      ),
    ).toBeNull();
    expect(parsePrivateReport(advisory({ created_at: "soon" }))).toBeNull();
  });

  test("the reader returns a complete list or unavailable, never a partial answer", async () => {
    const requests: { url: string; authorization: string | null }[] = [];
    let pages: Record<string, Response> = {};
    const reader = githubAdvisoryReader({
      apiOrigin: API,
      token: "fixture-read-token",
      fetch: async (url, init) => {
        requests.push({
          url,
          authorization: new Headers(init.headers).get("authorization"),
        });
        return pages[url] ?? new Response("{}", { status: 404 });
      },
    });
    const first = `${API}/repos/example/bounty/security-advisories?per_page=100&sort=created&direction=asc`;
    const second = `${API}/repos/example/bounty/security-advisories?per_page=100&page=2`;
    pages = {
      [first]: Response.json(
        [
          advisory({
            ghsa_id: "GHSA-2c3f-4g5h-6j7m",
            created_at: "2026-10-19T09:20:00Z",
          }),
          advisory({ ghsa_id: "GHSA-2c3f-4g5h-6j8m", submission: null }),
        ],
        { headers: { link: `<${second}>; rel="next"` } },
      ),
      [second]: Response.json([advisory()]),
    };
    const listed = await reader.privateReports("example/bounty");
    expect(listed.state).toBe("ok");
    expect(
      listed.state === "ok" ? listed.reports.map((r) => r.ghsa) : [],
    ).toEqual(["GHSA-7c8f-9g2h-3j4m", "GHSA-2c3f-4g5h-6j7m"]);
    expect(requests.map((r) => r.authorization)).toEqual([
      "Bearer fixture-read-token",
      "Bearer fixture-read-token",
    ]);
    // A failed later page, or a next link to another host, is not "no report".
    pages[second] = new Response("{}", { status: 502 });
    expect(await reader.privateReports("example/bounty")).toEqual({
      state: "unavailable",
    });
    pages[first] = Response.json([], {
      headers: { link: '<https://elsewhere.invalid/page>; rel="next"' },
    });
    expect(await reader.privateReports("example/bounty")).toEqual({
      state: "unavailable",
    });
    // A missing permission is unavailable too.
    pages[first] = new Response("{}", { status: 403 });
    expect(await reader.privateReports("example/bounty")).toEqual({
      state: "unavailable",
    });
    expect(await reader.privateReports("not a repository")).toEqual({
      state: "unavailable",
    });
  });
});

describe("analysis proposals", () => {
  test("a proposal can only name earlier cases it was given", () => {
    const proposal = parseAnalysisProposal(
      `Here is the JSON: ${JSON.stringify({
        summary: " Rounding drains the vault. ",
        severity: "critical",
        potentialLoss: "likely",
        duplicateCaseIds: ["sc_known00001", "sc_invented01", "sc_known00001"],
        rootCauseKey: "Not A Key",
        remediation: "Round down.",
      })}`,
      new Set(["sc_known00001"]),
    );
    expect(proposal).toEqual({
      summary: "Rounding drains the vault.",
      severity: "critical",
      potentialLoss: "likely",
      duplicateCaseIds: ["sc_known00001"],
      rootCauseKey: null,
      remediation: "Round down.",
    });
    expect(() =>
      parseAnalysisProposal(
        JSON.stringify({ ...proposal, severity: "pay-me" }),
        new Set(),
      ),
    ).toThrow();
  });
});
