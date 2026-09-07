import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { CandidateEvidence, candidateIsCurrent } from "./FixCandidates";
import { decodeFixCandidate, type ValidatedFixCandidate } from "./fix-candidate-client";
import { candidateFixture } from "./fix-candidate.fixture";

describe("candidate evidence display", () => {
  it("renders diff text and changed paths without treating repository content as markup", () => {
    const candidate = decodeFixCandidate(candidateFixture, "app-1") as ValidatedFixCandidate;
    const html = renderToStaticMarkup(createElement(CandidateEvidence, { candidate }));
    expect(html).toContain("&lt;script&gt;bad&lt;/script&gt;"); expect(html).toContain("&lt;img src=x onerror=bad()&gt;"); expect(html).not.toContain("<script>"); expect(html).not.toContain("<img");
    expect(html).toContain("临时容器已停止并清理"); expect(html).toContain("HTTP 200"); expect(html).not.toContain("发布成功");
  });
  it("keeps preparing, failed, and expired candidates ineligible", () => {
    const candidate = decodeFixCandidate(candidateFixture, "app-1");
    expect(candidateIsCurrent(candidate, Date.parse("2030-01-01T00:30:00Z"))).toBe(true);
    expect(candidateIsCurrent(candidate, Date.parse("2030-01-01T01:00:00Z"))).toBe(false);
    for (const status of ["preparing", "failed"]) expect(candidateIsCurrent(decodeFixCandidate({ ...candidateFixture, status }, "app-1"), 0)).toBe(false);
  });
});
