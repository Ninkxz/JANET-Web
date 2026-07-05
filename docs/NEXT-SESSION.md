# JANET Web -- Next-session prompt

Paste the block below to start the next build session. (Launch the session from
`X:\JANET Web` so the `project-janet-two` auto-memory loads.)

---

```
JANET Web build session. Project root: X:\JANET Web (private Gitea repo
bth0mp/J.A.N.E.T-TWO, branch main). The project-janet-two auto-memory has full context.

Read first, in order: docs\HANDOFF.md (the build guide -- section 11 is the concrete
Phase 0 checklist; sections 2-7 are the architecture + shared component kit), then
docs\ui-specs\message.md (the reference tool). Skim docs\REVIEW.md only if you need the
keep-vs-rebuild rationale.

Goal this session: execute Phase 0, then Build step 1 (Remote Message) end-to-end.
  0a. Lift JANET ONE's plumbing -> JanetWeb.* (rename only): server\JanetWeb.Server.ps1 /
      .Auth.ps1 / .Logging.ps1 (keep the SAME central-CSV log location), Start-JanetWeb.ps1
      (port 8089), Launch JANET Web.cmd, and server\tool-registry.json (12 tools, all
      ported:false). Reference plumbing in place at X:\J.A.N.E.T ONE\server\.
  0b. Build the shared frontend kit: web\css\janet.css (ThemeKit), web\js\shell.js
      (AppShell + router + view-registry + ctx + RunController extracted from JANET ONE
      app.js), web\js\components\* (CredSessionBar, TargetManager, RunBar, ConfirmDialog/
      ArmingDialog, ResultsGrid, ActivityLog, ProgressStatusStrip, StatCards, TabHost,
      ControlFactory). Verify with a mocked window.fetch job stream.
  1.  Re-fork the Remote Message engine from fork-source\Tools\RemoteMessageTool_1.3.3.ps1
      -> modules\JanetWeb.message.psm1 (cross-check X:\J.A.N.E.T ONE\modules\
      JanetOne.message.psm1). Build web\js\views\message.view.js per docs\ui-specs\
      message.md. Flip message to ported:true; verify end-to-end on the mocked stream.
      This view is the blueprint for the other 11 tools.

Non-negotiable rules: pure-PowerShell, zero third-party software; PS 5.1 must parse;
.ps1/.psm1 are UTF-8 WITH BOM + ASCII-only source (run the parse+BOM+ASCII gate after every
engine edit); NO generic renderer -- faithful per-tool views composing the shared kit, the
manifest is routing/audit only; ALL runs go through RunController (views never fetch/poll);
do NOT modify X:\J.A.N.E.T or X:\J.A.N.E.T ONE. Commit small (per component / per tool) and
push to bth0mp/J.A.N.E.T-TWO as you go (one-time `git -c http.extraHeader` Basic auth; keep
creds out of .git\config since the repo is on the shared SMB drive).

Gitea: http://100.119.34.30:3000/bth0mp/J.A.N.E.T-TWO  (I will paste the username + token.)
```

---

**Notes for the operator**
- Provide the Gitea credential at the start of the session (it is intentionally NOT stored
  in this repo). Consider issuing a dedicated Gitea **access token** instead of the account
  password (Settings -> Applications -> Generate Token), since the password has been pasted
  into chat history.
- If anything in `docs\HANDOFF.md` should change (build order, theme, port), say so before
  Phase 0 -- it is cheaper to adjust the plan than the code.
