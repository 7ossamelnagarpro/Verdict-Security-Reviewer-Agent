# Security Lab Web

Educational Flask + SQLite web application for local security testing. It is
deliberately unsafe: run it only on `127.0.0.1` or in an isolated test
environment, never on a public or shared network.

Install the declared dependency, then start the application:

```powershell
python -m pip install -r requirements.txt
python app.py
```

The application listens on `http://127.0.0.1:5000/` by default. The benchmark
labels and test scenarios are kept outside this scan target so they cannot be
mistaken for application evidence.

For the trusted local Docker lab, `Dockerfile` builds the application and
`compose.yaml` publishes it only on host `127.0.0.1:5055`. Do not run this
intentionally vulnerable fixture on a public or shared network. See the
[automatic Docker scan instructions](../../docs/docker-automatic-runtime.md).
